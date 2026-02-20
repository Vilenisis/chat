#include <Adafruit_GFX.h>
#include <Adafruit_TFTLCD.h>
#include <SPI.h>

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
static uint16_t linePos = 0;
static int16_t y = 22;
const int16_t lineHeight = 16;

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

      // Убираем префикс "MSG: " от клиента
      const char* msg = lineBuf;
      if (linePos >= 5 &&
          lineBuf[0] == 'M' && lineBuf[1] == 'S' && lineBuf[2] == 'G' &&
          lineBuf[3] == ':' && lineBuf[4] == ' ') {
        msg = lineBuf + 5;
      }

      if (*msg) {
        printLine(msg, WHITE);
        Serial.print("OK: ");
        Serial.println(msg);
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
