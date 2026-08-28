// Heavily modified from the "ThumbySimpleExample" project
#include "Ascon.h"
#include <Thumby.h>
#include <ctype.h>
#include <stdlib.h>
#include "hardware/regs/rosc.h"
#include "hardware/regs/addressmap.h"

//When defined, skips encryption/decryption (for testing power consumption)
//#define SKIP_CRYPTO
//When defined, skips ALL communication (for testing purposes)
//#define SKIP_COMMS

volatile uint32_t *rnd_reg=(uint32_t *)(ROSC_BASE + ROSC_RANDOMBIT_OFFSET);

Thumby thumby = Thumby();

const size_t THUMBY_SCREEN_CHAR_WIDTH = 12;
const size_t THUMBY_LINK_MAX = 512;

//simple class to allow viewing long text on the Thumby
class WriteableBuffer
{
  private:
    size_t size = 0;
    char* buffer;
    size_t viewOffset = 0;
    size_t writeOffset = 0;
    bool readonly = false;

  public:
    WriteableBuffer(char* _buffer, size_t _size, bool _readonly)
    {
      assert(alignof(buffer) == alignof(uint32_t));
      buffer = _buffer;
      size = _size;
      readonly = _readonly;
    }

    size_t get_size() { return size; }
    size_t get_used() { return strlen(buffer); }

    void UpdateView()
    {
      if(writeOffset < viewOffset)
        viewOffset = writeOffset;
      else if(viewOffset + THUMBY_SCREEN_CHAR_WIDTH < writeOffset)
        viewOffset = writeOffset - THUMBY_SCREEN_CHAR_WIDTH + 1;
    }

    void UpdateCursor()
    {
      assert(0 <= writeOffset && writeOffset <= size - 1);
      size_t max = strlen(buffer);
      if(max <= writeOffset)
        writeOffset = max;

      UpdateView();
    }

    void Move(int8_t move)
    {
      if(move == 0)
        return;
      if(move > 0)
      {
        if(writeOffset < size - 1 && buffer[writeOffset] != '\0')
          writeOffset++;
      }
      else //if(move < 0)
      {
        if(0 < writeOffset)
          writeOffset--;
      }

      UpdateView();
    }

    void Toggle(bool toggle)
    {
      if(readonly)
        return;
      assert(0 <= writeOffset && writeOffset <= size - 1);
      if(!toggle)
        return;

      char* c = &buffer[writeOffset];
      if(*c == '\0')
      {
        *c = 'a';
      }
      else if('a' <= *c && *c <= 'z')
      {
        *c &= ~0x20;
      }
      else if('A' <= *c && *c <= 'Z')
      {
        *c = '0';
      }
      else if('0' <= *c && *c <= '9')
      {
        *c = '_';
      }
      else
      {
        *c = '\0';
      }
    }

    void Increment(int8_t inc)
    {
      if(readonly)
        return;
      assert(0 <= writeOffset && writeOffset <= size - 1);
      if(inc == 0)
        return;
      char* c = &buffer[writeOffset];
      if(*c == '\0')
        return;

      if(inc > 0)
      {
        //overflow
        switch(*c)
        {
          case 'z':
            *c = 'a';
            break;
          case 'Z':
            *c = 'A';
            break;
          case '9':
            *c = '0';
            break;
          default:
            (*c)++;
            break;
        }
      }
      else //if(inc < 0)
      {
        //underflow
        switch(*c)
        {
          case 'a':
            *c = 'z';
            break;
          case 'A':
            *c = 'Z';
            break;
          case '0':
            *c = '9';
            break;
          default:
            (*c)--;
            break;
        }
      }
    }

    void Display(bool selected)
    {
      assert(0 <= viewOffset && viewOffset <= size - 1 - THUMBY_SCREEN_CHAR_WIDTH);
      assert(0 <= writeOffset && writeOffset <= size - 1);
      if(selected)
      {
        char sel = buffer[writeOffset];
        buffer[writeOffset] = '\0';
        thumby.print(buffer + viewOffset);
        thumby.fontColor(0, 0xFFFF);
        thumby.print(sel);
        buffer[writeOffset] = sel;
        thumby.fontColor(0xFFFF, 0);
        if(sel != 0)
          thumby.print(buffer + writeOffset + 1);
      }
      else
      {
        thumby.print(buffer+viewOffset);
      }
    }
};
//header for serial communication
struct PacketHeader
{
  uint16_t additionalLength;
  uint16_t ciphertextLength;
  uint64_t nonce[2];
};

uint64_t tagOut[2];
uint64_t tagIn[2];

//                            max buff       - overhead                              + 1 for null terminator
const size_t EFFECTIVE_MAX = THUMBY_LINK_MAX - sizeof(PacketHeader) - sizeof(tagOut) + 1;
alignas(4) uint8_t ciphertextIn[EFFECTIVE_MAX];
alignas(4) char plaintextIn[EFFECTIVE_MAX];
alignas(4) char plaintextOut[EFFECTIVE_MAX];

//additional data 
union additionalBuffer
{
  PacketHeader header;
  alignas(4) char buffer[sizeof(PacketHeader) + EFFECTIVE_MAX];
}
additionalOut,
additionalIn;

//the plaintext writer gets the whole buffer
WriteableBuffer plaintextWriter(plaintextOut, sizeof(plaintextOut), false);
WriteableBuffer plaintextReader(plaintextIn, sizeof(plaintextIn), true);

//for the additional data, we need to skip over the required header
WriteableBuffer additionalWriter(additionalOut.buffer + sizeof(PacketHeader), sizeof(additionalOut.buffer) - sizeof(PacketHeader), false);
WriteableBuffer additionalReader(additionalIn.buffer  + sizeof(PacketHeader), sizeof(additionalIn.buffer)  - sizeof(PacketHeader), true);

uint64_t key[2] =
{
  0x00D00D0BA17ED000,
  0x00F00D0A7ED02025
};
alignas(4) uint8_t ciphertextOut[EFFECTIVE_MAX];


// Removes all bytes from RX buffer (use after writing on Serial1)
void removeRxBytes()
{
  delay(10);
  while(Serial1.available() > 0){
    Serial1.read();
  }
}

uint32_t randBuff = 0;
uint32_t sendTimer = 0;

void resetTimer(uint8_t bits, uint8_t shift)
{
  assert(bits > 0);
  //mask for the lowest "bits" bits
  uint32_t mask = 0xFFFFFFFF >> (32 - bits);
  do
  {
    //fill up the random buffer if it's empty
    if(randBuff == 0)
      randBuff = rand();

    sendTimer = (randBuff & mask) << shift;
    randBuff >>= bits;

  } while(sendTimer == 0);
}

bool waitToSend()
{
  return (sendTimer-- == 0);
}

void setup()
{
  // Sets up buttons, audio, link pins, and screen
  thumby.begin();
  Serial1.setTimeout(100);

  //uses the ring oscillator as a (non cryptographic) random number generator
  uint32_t seed = 0;
  for(size_t i = 0; i < 32; i++)
  {
    seed <<= 1;
    seed |= (*rnd_reg & 1);
  }
  //use that to init rand() and the thus timer
  srand(seed);
  resetTimer(4,6);

  //setup plaintext
  memset(plaintextOut, 0, sizeof(plaintextOut));
  strcpy(plaintextOut, "Plaintext");
  
  //additional data
  memset(additionalOut.buffer, 0, sizeof(additionalOut.buffer));
  strcpy(additionalOut.buffer + sizeof(PacketHeader), "Additional");
  
  //tag
  memset(tagOut, 0, sizeof(tagOut));

  //and the same thing but for input not output
  memset(tagIn, 0, sizeof(tagIn));
  memset(plaintextIn, 0, sizeof(plaintextIn));
  memset(additionalIn.buffer, 0, sizeof(additionalIn.buffer));


  // Init duplex UART for Thumby to PC comms
  //Serial.begin(115200);

  // Make sure RX buffer is empty
  removeRxBytes();
}

bool L_held = false;
bool R_held = false;

bool D_held = false;
bool U_held = false;

bool A_held = false;
bool B_held = false;


void getInput(uint8_t& selected, bool& toggle, int8_t& move, int8_t& increment)
{
  //B swaps between editing the plaintext and the additional data
  bool B_pressed = thumby.isPressed(BUTTON_B);
  if(B_pressed && !B_held)
    selected = (selected + 1) % 4;
  B_held = B_pressed;

  //L/R changes index to edit
  move = 0;
  bool L_pressed = thumby.isPressed(BUTTON_L);
  bool R_pressed = thumby.isPressed(BUTTON_R);
  if(L_pressed ^ R_pressed && (L_pressed != L_held || R_pressed != R_held))
  {
    move += R_pressed ? 1 : 0;
    move -= L_pressed ? 1 : 0;
  }
  L_held = L_pressed;
  R_held = R_pressed;

  //A toggles if the current letter is included
  bool A_pressed = thumby.isPressed(BUTTON_A);
  toggle = A_pressed && !A_held;
  A_held = A_pressed;

  //U/D increment/decrement the character
  increment = 0;
  bool D_pressed = thumby.isPressed(BUTTON_D);
  bool U_pressed = thumby.isPressed(BUTTON_U);
  if(D_pressed ^ U_pressed && (D_pressed != D_held || U_pressed != U_held))
  {
    increment += U_pressed ? 1 : 0;
    increment -= D_pressed ? 1 : 0;
  }
  D_held = D_pressed;
  U_held = U_pressed;
}

uint8_t linkBuff[THUMBY_LINK_MAX];

int32_t decodeStatus = 0;
size_t lastRead;
int32_t tryDecode()
{
  int avail = Serial1.available();
  
  //skip if no incoming message
  if(avail <= 0)
    return -1;

  memset(linkBuff, 0, sizeof(linkBuff));
  lastRead = Serial1.readBytes(linkBuff, THUMBY_LINK_MAX);
  decodeStatus = 0;
  if(lastRead != THUMBY_LINK_MAX) //partial header?
  {
    return 1;
  }
  PacketHeader* ph = (PacketHeader*)&linkBuff;
  if(ph->additionalLength < sizeof(PacketHeader)) //additional didn't include the header?
  {
    return 2;
  }
  if(ph->additionalLength - sizeof(PacketHeader) > THUMBY_LINK_MAX) //too much additional data
  {
    return 3;
  }
  if(ph->ciphertextLength < 0) //invalid ciphertext length
  {
    return 4;
  }
  if(ph->ciphertextLength > THUMBY_LINK_MAX) //too much ciphertext
  {
    return 5;
  }


  memset(additionalIn.buffer, 0, sizeof(additionalIn.buffer));
  memcpy(additionalIn.buffer, linkBuff, ph->additionalLength);
  memset(ciphertextIn, 0, sizeof(ciphertextIn));
  memcpy(ciphertextIn, linkBuff + ph->additionalLength, ph->ciphertextLength);
  memcpy(tagIn, linkBuff + ph->additionalLength + ph->ciphertextLength, sizeof(tagIn));

  //try decode
  memset(plaintextIn, 0, sizeof(plaintextIn));
  bool decodeOk =
  #ifdef SKIP_CRYPTO
    true;
    memcpy(plaintextIn, ciphertextIn, additionalIn.header.ciphertextLength);
  #else
    Ascon_AEAD128_Decode(key, additionalIn.header.nonce,
      (uint8_t*)additionalIn.buffer, additionalIn.header.additionalLength,
      (uint8_t*)ciphertextIn, additionalIn.header.ciphertextLength,
      (uint8_t*)plaintextIn, tagIn);
  #endif
  if(decodeOk)
  {
    return 0;
  }
  else
  {
    memset(plaintextIn, 0, sizeof(plaintextIn));
    return 9;
  }
}

void sendMessage()
{
  //encode/send the message
  additionalOut.header.additionalLength = sizeof(PacketHeader) + additionalWriter.get_used();
  additionalOut.header.ciphertextLength = plaintextWriter.get_used();
  #ifdef SKIP_CRYPTO
  memcpy(ciphertextOut, plaintextOut, plaintextWriter.get_used());
  #else
  Ascon_AEAD128_Encode(key, additionalOut.header.nonce,
    (uint8_t*)additionalOut.buffer, additionalOut.header.additionalLength,
    (uint8_t*)plaintextOut, plaintextWriter.get_used(),
    (uint8_t*)ciphertextOut, tagOut);
  #endif
  size_t size = additionalOut.header.additionalLength;
  memcpy(linkBuff, additionalOut.buffer, size);
  memcpy(linkBuff + size, ciphertextOut, additionalOut.header.ciphertextLength);
  size += additionalOut.header.ciphertextLength;
  memcpy(linkBuff + size, (uint8_t*)tagOut, sizeof(tagOut));
  size += sizeof(tagOut);

  if(Serial1.available() <= 0)
    Serial1.write(linkBuff, THUMBY_LINK_MAX);
  removeRxBytes();

  //clear buffers after they've been sent
  memset(linkBuff, 0, size);
  memset(ciphertextOut, 0, sizeof(ciphertextOut));
  memset(tagOut, 0, sizeof(tagOut));
}


uint8_t selected = 0;
WriteableBuffer* buffs[4] = { &plaintextWriter, &additionalWriter, &plaintextReader, &additionalReader };
void loop()
{
  // Clear the screen to black
  thumby.clear();

  //get input
  bool toggle = false;
  int8_t move = 0;
  int8_t inc  = 0;
  getInput(selected, toggle, move, inc);

  //update the selected buffer
  WriteableBuffer* buff = buffs[selected];
  buff->Move(move);
  buff->Toggle(toggle);
  buff->Increment(inc);

  //display buffers
  thumby.setCursor(0, 0);
  plaintextWriter.Display(selected == 0);
  thumby.setCursor(0, 10);
  additionalWriter.Display(selected == 1);
  
  #ifndef SKIP_COMMS
  //try and decode any incoming message
  int32_t td = tryDecode();
  
  //if we got ANY message
  if(td >= 0)
  {
    //update the decode status
    decodeStatus = td;
    resetTimer(4,4);

    //otherwise, try to clear out any partial/failed messages
    if(td > 0)
    {
      removeRxBytes();
    }
  }
  //otherwise, if we've waited long enough, send again
  else if(waitToSend())
  {
    sendMessage();
    //low bits are random
    resetTimer(4,4);
    //minimum of 1024
    sendTimer |= (1 << 11);
  }
  #endif
  
  thumby.setCursor(0, 20);
  if(decodeStatus == 0)
  {
    plaintextReader.UpdateCursor();
    plaintextReader.Display(selected == 2);
    thumby.setCursor(0, 30);
    additionalReader.UpdateCursor();
    additionalReader.Display(selected == 3);
  }
  else
  {
    selected &= 1;
    thumby.print("Decode error ");
    thumby.print(decodeStatus);
    //*
    thumby.setCursor(0, 30);
    thumby.print(sendTimer);
    //*/
  }
  
  thumby.writeBuffer(thumby.getBuffer(), thumby.getBufferSize());
}
