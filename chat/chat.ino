#include <Adafruit_GFX.h>
#include <Adafruit_TFTLCD.h>
#include <SPI.h>
#include <string.h>

#define LCD_CS    A3
#define LCD_CD    A2
#define LCD_WR    A1
#define LCD_RD    A0
#define LCD_RESET A4

Adafruit_TFTLCD tft(LCD_CS, LCD_CD, LCD_WR, LCD_RD, LCD_RESET);

#define BLACK 0x0000
#define WHITE 0xFFFF
#define GREEN 0x07E0

static char lineBuf[256];
static char outBuf[256];
static uint16_t linePos = 0;
static int16_t y = 22;
const int16_t lineHeight = 16;

bool isStatusToken(const char* token, uint16_t len) {
  if (len < 2 || len > 12) return false;

  char lowered[16];
  uint16_t w = 0;
  bool hasColon = false;

  for (uint16_t i = 0; i < len && w < sizeof(lowered) - 1; ++i) {
    char c = token[i];
    if (c == ':') {
      hasColon = true;
      continue;
    }
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
      return false;
    }
    if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
    lowered[w++] = c;
  }
  lowered[w] = '\0';

  if (hasColon) return true;
  return strcmp(lowered, "sys") == 0 || strcmp(lowered, "msg") == 0 ||
         strcmp(lowered, "ok") == 0 || strcmp(lowered, "err") == 0 ||
         strcmp(lowered, "bot") == 0 || strcmp(lowered, "user") == 0;
}

uint8_t utf8CharLen(uint8_t lead) {
  if ((lead & 0x80) == 0x00) return 1;
  if ((lead & 0xE0) == 0xC0) return 2;
  if ((lead & 0xF0) == 0xE0) return 3;
  if ((lead & 0xF8) == 0xF0) return 4;
  return 1;
}

uint16_t appendWord456(const char* word, uint16_t len, char* out, uint16_t outPos) {
  uint16_t i = 0;
  uint16_t charIndex = 1;

  while (i < len && outPos < sizeof(outBuf) - 1) {
    uint8_t step = utf8CharLen((uint8_t)word[i]);
    if (i + step > len) {
      step = 1;
    }

    if (charIndex >= 4 && charIndex <= 6) {
      for (uint8_t j = 0; j < step && outPos < sizeof(outBuf) - 1; ++j) {
        out[outPos++] = word[i + j];
      }
    }

    i += step;
    ++charIndex;
  }

  return outPos;
}

void transformMessage(const char* input, char* output) {
  uint16_t inPos = 0;
  uint16_t outPos = 0;
  bool firstTokenWritten = false;

  while (input[inPos] != '\0') {
    while (input[inPos] == ' ' || input[inPos] == '\t') {
      ++inPos;
    }
    if (input[inPos] == '\0') break;

    uint16_t start = inPos;
    while (input[inPos] != '\0' && input[inPos] != ' ' && input[inPos] != '\t') {
      ++inPos;
    }
    uint16_t len = inPos - start;
    if (len == 0) continue;

    char token[128];
    uint16_t copyLen = len < sizeof(token) - 1 ? len : sizeof(token) - 1;
    memcpy(token, input + start, copyLen);
    token[copyLen] = '\0';

    char part[128];
    uint16_t partLen = 0;

    if (isStatusToken(token, copyLen)) {
      partLen = copyLen;
      memcpy(part, token, partLen);
    } else {
      partLen = appendWord456(token, copyLen, part, 0);
    }

    if (partLen == 0) continue;

    if (firstTokenWritten && outPos < sizeof(outBuf) - 1) {
      output[outPos++] = ' ';
    }

    for (uint16_t i = 0; i < partLen && outPos < sizeof(outBuf) - 1; ++i) {
      output[outPos++] = part[i];
    }

    firstTokenWritten = true;
  }

  output[outPos] = '\0';
}

void printLine(const char* text, uint16_t color = WHITE) {
  if (y > tft.height() - lineHeight) {
    tft.fillScreen(BLACK);   // простой "скролл": очистка
    y = 22;
    tft.setCursor(8, 4);
    tft.setTextColor(GREEN);
    tft.setTextSize(2);
    tft.print("CHAT");
  }

  tft.setCursor(8, y);
  tft.setTextColor(color);
  tft.setTextSize(2);
  tft.print(text);
  y += lineHeight;
}

void setup() {
  Serial.begin(115200);
  while (!Serial) {}

  tft.reset();

  uint16_t identifier = tft.readID();
  if (identifier == 0x0101 || identifier == 0xFFFF || identifier == 0x0000) {
    identifier = 0x9341; // fallback для частых 2.4" TFT
  }
  tft.begin(identifier);

  tft.setRotation(1);
  tft.fillScreen(BLACK);
  tft.drawRect(0, 0, tft.width(), tft.height(), WHITE);

  tft.setCursor(8, 4);
  tft.setTextColor(GREEN);
  tft.setTextSize(2);
  tft.print("CHAT");

  printLine("READY", WHITE);
  Serial.println("CHAT_READY");
}

void loop() {
  while (Serial.available() > 0) {
    char c = (char)Serial.read();

    if (c == '\r') continue;

    if (c == '\n') {
      lineBuf[linePos] = '\0';

      transformMessage(lineBuf, outBuf);
      const char* msg = outBuf;

      if (*msg) {
        printLine(msg, WHITE);
        Serial.print("OK: ");
        Serial.print(msg);
        Serial.print('\n');
      }

      linePos = 0;
    } else {
      if (linePos < sizeof(lineBuf) - 1) {
        lineBuf[linePos++] = c;
      } else {
        linePos = 0; // защита от переполнения
      }
    }
  }
}
