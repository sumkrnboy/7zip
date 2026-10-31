// MirayHandler.cpp - MFI/MAI disk-image reader

#include "StdAfx.h"

#include "../../../C/7zCrc.h"
#include "../../../C/Alloc.h"
#include "../../../C/Aes.h"
#include "../../../C/CpuArch.h"
#include "../../../C/LzmaDec.h"
#include "../../../C/Sha256.h"

#include "../../Common/ComTry.h"
#include "../../Common/IntToString.h"
#include "../../Common/MyBuffer.h"
#include "../../Common/UTFConvert.h"
#include "../../Windows/PropVariant.h"

#include "../Common/RegisterArc.h"
#include "../Common/CreateCoder.h"
#include "../Common/LimitedStreams.h"
#include "../Common/StreamObjects.h"
#include "../Common/StreamUtils.h"
#include "../Compress/ZlibDecoder.h"
#include "../IPassword.h"
#include "HandlerCont.h"
#include "Common/MultiStream.h"

using namespace NWindows;

namespace NArchive {
namespace NMiray {

static const UInt32 kMetadataLimit = 1 << 24;
static const UInt32 kBlockLimit = 1 << 26;
static const unsigned kItemLimit = 1 << 20;
static const Byte kSignatures[] = { 4, 'M', 'S', 'F', 'C', 4, 'H', 'S', 'A', 'M' };
static const Byte kMsfcSignature[] = {
  'M', 'S', 'F', 'C', 0x61, 0x11, 0x5b, 0xc7, 0xb1, 0xf6,
  0x7a, 0x4a, 0x92, 0xfb, 0xac, 0xd3, 0x73, 0x71, 0x3e, 0x06
};
// Image-format wrapping slot 9; the password-derived key unwraps the outer layer.
static const Byte kImageWrapKey[32] = {
  0x47,0x5a,0xdf,0x9b,0x87,0x70,0x3a,0x15,0x31,0xfe,0xd1,0x8d,0xd2,0x73,0x12,0xf9,
  0x54,0xa7,0x40,0x7c,0x59,0x28,0x2b,0x13,0x75,0x15,0xcf,0xb6,0xd5,0x77,0x9a,0x60
};

// Legacy image-format wrapping slot 5.
static const Byte kLegacyImageWrapKey[32] = {
  0xde,0x06,0x46,0xa3,0xa1,0xc2,0xad,0xd3,0x36,0x73,0x0e,0x71,0xf3,0x33,0x3f,0x34,
  0xbc,0x8b,0xfc,0x20,0x3e,0xe8,0x73,0x1b,0xe6,0x06,0xfc,0x08,0xc1,0x14,0x92,0xf2
};

static const Byte *GetImageWrapKey(UInt32 slot)
{
  return slot == 9 ? kImageWrapKey : slot == 5 ? kLegacyImageWrapKey : NULL;
}

static void HashKeyData(CSha256 *hash, const Byte *data, size_t size)
{
  // Metadata fields can be unaligned. Short updates use the hash's aligned buffer.
  while (size)
  {
    const size_t take = size < 64 ? size : 63;
    Sha256_Update(hash, data, take);
    data += take;
    size -= take;
  }
}

#define MIRAY_CHECK(c) if (!(c)) return S_FALSE;

// Byte loads support unaligned disk fields.
static UInt16 Read16(const Byte *p)
{
  return (UInt16)((UInt16)p[0] | ((UInt16)p[1] << 8));
}

static UInt32 Read32(const Byte *p)
{
  return (UInt32)p[0] | ((UInt32)p[1] << 8)
      | ((UInt32)p[2] << 16) | ((UInt32)p[3] << 24);
}

static UInt64 Read64(const Byte *p)
{
  return (UInt64)Read32(p) | ((UInt64)Read32(p + 4) << 32);
}

struct CExtent
{
  UInt64 Offset;
  UInt64 Size;
};

struct COverlayMap
{
  unsigned Width;
  unsigned Levels;
  UInt32 Entries[6];
  UInt64 Span[6];
  UInt64 End;
};

struct CImageStream
{
  AString Name;
  UInt64 Size;
  CRecordVector<CExtent> Extents;
};

static void AddChunkExtent(CImageStream &stream, UInt64 offset, UInt64 size)
{
  if (!stream.Extents.IsEmpty()
      && stream.Extents.Back().Offset + stream.Extents.Back().Size == offset)
    stream.Extents.Back().Size += size;
  else
  {
    CExtent extent;
    extent.Offset = offset;
    extent.Size = size;
    stream.Extents.Add(extent);
  }
}

struct CImageChecksum
{
  unsigned StreamIndex;
  unsigned Method;
  bool Physical;
  Byte Digest[32];
};

static const unsigned kDigestSizes[] = { 16, 20, 32, 32 };

struct CBlock
{
  UInt64 Virt;
  UInt64 Pos;
  UInt32 Packed;
  UInt32 Unpacked;
  unsigned Part;
  bool Compressed;
};

static int CompareBlocks(const CBlock *a, const CBlock *b, void *)
{
  return a->Virt < b->Virt ? -1 : a->Virt == b->Virt ? 0 : 1;
}

struct CPart
{
  AString Name;
  UInt64 Base;
  UInt64 Sectors;
  UInt64 Stored;
  UInt64 Last;
  UInt64 StoredBytes;
  UInt32 Method;
  UInt32 Kind;
  unsigned StreamIndex;
  Byte LzmaProps[LZMA_PROPS_SIZE];
  bool HasLzmaProps;
  bool HasLast;
  bool HasStoredBytes;
  CRecordVector<CExtent> Errors;
  CPart(): Base(0), Sectors(0), Stored(0), Last(0), StoredBytes(0), Method(0), Kind(0), StreamIndex(0),
      HasLzmaProps(false), HasLast(false), HasStoredBytes(false) {}
};

static bool IsUnavailableRange(const CPart &part, UInt64 start, UInt64 end)
{
  if (start == end)
    return true;
  unsigned low = 0, high = part.Errors.Size();
  while (low < high)
  {
    const unsigned mid = low + (high - low) / 2;
    if (part.Errors[mid].Offset <= start)
      low = mid + 1;
    else
      high = mid;
  }
  for (unsigned i = low ? low - 1 : 0; i < part.Errors.Size(); i++)
  {
    const CExtent &error = part.Errors[i];
    if (error.Offset > start)
      return false;
    const UInt64 stop = error.Offset + error.Size;
    if (stop > start)
    {
      if (stop >= end)
        return true;
      start = stop;
    }
  }
  return false;
}

static bool CheckZeroCrc(CByteBuffer &data)
{
  const UInt32 crc = Read32(data + 8);
  SetUi32(data + 8, 0);
  const bool result = CrcCalc(data, data.Size()) == crc;
  SetUi32(data + 8, crc);
  return result;
}

static bool Lz4Length(const Byte *src, size_t size, size_t &pos, size_t limit, size_t &length)
{
  if (length == 15)
    for (;;)
    {
      if (pos == size)
        return false;
      const unsigned n = src[pos++];
      if (length > limit || n > limit - length)
        return false;
      length += n;
      if (n != 255)
        break;
    }
  return length <= limit;
}

static bool CheckPadding(const Byte *src, size_t size, size_t consumed, bool encrypted)
{
  if (consumed == size)
    return true;
  if (!encrypted || consumed > size || size - consumed >= AES_BLOCK_SIZE)
    return false;
  for (; consumed < size; consumed++)
    if (src[consumed] != 0)
      return false;
  return true;
}

static bool DecodeLz4(const Byte *src, size_t size, Byte *dest, size_t expected, bool encrypted)
{
  size_t pos = 0, out = 0;
  while (pos < size)
  {
    const unsigned token = src[pos++];
    size_t length = token >> 4;
    if (!Lz4Length(src, size, pos, expected - out, length)
        || length > size - pos)
      return false;
    memcpy(dest + out, src + pos, length);
    out += length;
    pos += length;
    if (encrypted && out == expected)
      return CheckPadding(src, size, pos, true);
    if (pos == size)
      return out == expected;
    if (size - pos < 2)
      return false;
    const unsigned distance = Read16(src + pos);
    pos += 2;
    if (distance == 0 || distance > out)
      return false;
    length = token & 15;
    if (!Lz4Length(src, size, pos, expected - out, length)
        || expected - out < 4 || length > expected - out - 4)
      return false;
    length += 4;
    const size_t origin = out - distance;
    while (length)
    {
      const size_t available = out - origin;
      const size_t take = length < available ? length : available;
      memcpy(dest + out, dest + origin, take);
      out += take;
      length -= take;
    }
  }
  return out == expected;
}

static void HashPassword(const Byte *data, size_t size, const Byte *salt, Byte *digest)
{
  CSha256 hash;
  Sha256_Init(&hash);
  if (salt)
    Sha256_Update(&hash, salt, SHA256_DIGEST_SIZE);
  Sha256_Update(&hash, data, size);
  Sha256_Final(&hash, digest);
}

static bool DecryptEcb(Byte *data, size_t size, const Byte *key, unsigned keySize)
{
  if (size % AES_BLOCK_SIZE)
    return false;
  MY_ALIGN(16) UInt32 aes[AES_NUM_IVMRK_WORDS];
  MY_ALIGN(16) Byte buffer[4096];
  Aes_SetKey_Dec(aes + 4, key, keySize);
  while (size)
  {
    const size_t take = size < sizeof(buffer) ? size : sizeof(buffer);
    memcpy(buffer, data, take);
    memset(aes, 0, AES_BLOCK_SIZE);
    // Undo CBC's previous-block xor to obtain ECB using the existing AES code.
    // Ciphertext remains intact until the decrypted bytes are copied back.
    g_AesCbc_Decode(aes, buffer, take / AES_BLOCK_SIZE);
    for (size_t i = AES_BLOCK_SIZE; i < take; i++)
      buffer[i] ^= data[i - AES_BLOCK_SIZE];
    memcpy(data, buffer, take);
    data += take;
    size -= take;
  }
  memset(aes, 0, sizeof(aes));
  memset(buffer, 0, sizeof(buffer));
  return true;
}

static HRESULT AddVolumeRange(CMultiStream *combined, IInStream *input, UInt64 offset, UInt64 size)
{
  CMyComPtr2<IInStream, CLimitedInStream> limited;
  limited.Create_if_Empty();
  limited->SetStream(input);
  RINOK(limited->InitAndSeek(offset, size))
  CMultiStream::CSubStreamInfo entry;
  entry.Stream = limited;
  entry.Size = size;
  combined->Streams.Add(entry);
  return S_OK;
}

static void AddVolumeRecord(CMultiStream *combined, const Byte *data)
{
  CReferenceBuf *reference = new CReferenceBuf;
  CMyComPtr<IUnknown> owner = reference;
  reference->Buf.CopyFrom(data, 4096);
  CMyComPtr2<IInStream, CBufInStream> input;
  input.Create_if_Empty();
  input->Init(reference);
  CMultiStream::CSubStreamInfo entry;
  entry.Stream = input;
  entry.Size = 4096;
  combined->Streams.Add(entry);
}

Z7_class_CHandler_final: public CHandlerImg
{
  Z7_IFACE_COM7_IMP(IInArchive_Img)
  Z7_IFACE_COM7_IMP(IInArchiveGetStream)
  Z7_IFACE_COM7_IMP(ISequentialInStream)

  CObjectVector<CImageStream> _streams;
  CObjectVector<CPart> _parts;
  CRecordVector<CExtent> _maiVolumes;
  CObjectVector<CByteBuffer> _maiVolumeRecords;
  CRecordVector<CImageChecksum> _maiChecksums;
  CSha256 _keyPrefixHash;
  CRecordVector<CBlock> _blocks;
  CRecordVector<CExtent> _unavailable;
  UInt64 _phySize;
  UInt64 _totalPhysicalSize;
  UInt64 _firstPhysicalSize;
  UInt32 _numVolumes;
  UInt32 _maiChunkSize;
  UInt32 _maiMaxChunks;
  UInt64 _splitSize;
  UInt32 _sectorSize;
  UInt32 _method;
  UInt32 _version;
  unsigned _cacheIndex;
  unsigned _depth;
  bool _isMai;
  bool _smart;
  bool _dependent;
  bool _rawImage;
  bool _overlay;
  bool _growableMfi;
  UInt32 _encryption;
  bool _protected;
  CByteBuffer _salt, _verifier, _keyStore, _key;
  CByteBuffer _imageId, _baseId;
  UString _parentName, _sourceName;
  CMyComPtr<IInStream> _base;
  CByteBuffer _cache;
  CByteBuffer _packed;
  CMyComPtr2<ISequentialInStream, CBufInStream> _bufIn;
  CMyComPtr2<ISequentialOutStream, CBufPtrSeqOutStream> _bufOut;
  CMyComPtr2<ICompressCoder, NCompress::NZlib::CDecoder> _zlib;

  HRESULT ReadAt(UInt64 pos, void *data, size_t size)
  {
    MIRAY_CHECK(pos <= _phySize && size <= _phySize - pos)
    RINOK(InStream_SeekSet(Stream, pos))
    return ReadStream_FALSE(Stream, data, size);
  }

  HRESULT ReadData(const CImageStream &s, UInt64 pos, void *data, size_t size)
  {
    MIRAY_CHECK(pos <= s.Size && size <= s.Size - pos)
    Byte *dest = (Byte *)data;
    FOR_VECTOR (i, s.Extents)
    {
      const CExtent &e = s.Extents[i];
      if (pos >= e.Size)
      {
        pos -= e.Size;
        continue;
      }
      const size_t take = (UInt64)size < e.Size - pos ? size : (size_t)(e.Size - pos);
      RINOK(ReadAt(e.Offset + pos, dest, take))
      size -= take;
      dest += take;
      if (!size)
        return S_OK;
      pos = 0;
    }
    return size == 0 ? S_OK : S_FALSE;
  }

  HRESULT CheckStream(const CImageStream &s)
  {
    MIRAY_CHECK(!s.Name.IsEmpty())
    UInt64 total = 0;
    FOR_VECTOR (i, s.Extents)
    {
      const CExtent &e = s.Extents[i];
      MIRAY_CHECK(e.Offset <= _phySize && e.Size <= _phySize - e.Offset)
      MIRAY_CHECK(total <= (UInt64)(Int64)-1 - e.Size)
      total += e.Size;
    }
    MIRAY_CHECK(total >= s.Size)
    for (unsigned i = 0; i + 1 < _streams.Size(); i++)
      MIRAY_CHECK(s.Name != _streams[i].Name)
    return S_OK;
  }

  HRESULT OpenMfi(IArchiveOpenCallback *openCallback);
  HRESULT ReadDirectoryData(const CImageStream &directory, UInt64 base,
      UInt64 chunk, UInt64 position, void *data, size_t size)
  {
    MIRAY_CHECK(position <= directory.Size && size <= directory.Size - position)
    if (position < chunk && size <= chunk - position)
      return ReadAt(base + position, data, size);
    return ReadData(directory, position, data, size);
  }
  HRESULT OpenVolumes(const Byte *header, IArchiveOpenCallback *openCallback);
  HRESULT OpenMai(IArchiveOpenCallback *openCallback);
  HRESULT OpenMaiVolumes(const Byte *header, const Byte *footer, IArchiveOpenCallback *openCallback);
  HRESULT ReadMaiChecksums(const CByteBuffer &descriptor, UInt32 offset, UInt32 size,
      unsigned streamIndex, bool physical = false);
  HRESULT VerifyMaiChecksums();
  HRESULT ReadMetadata();
  HRESULT ReadKeyStore(CRecordVector<UInt32> &offsets);
  HRESULT OpenBase(IArchiveOpenCallback *openCallback);
  HRESULT Unlock(IArchiveOpenCallback *openCallback);
  HRESULT ReadBlocks();
  HRESULT ReadPartBlocks(unsigned partIndex);
  HRESULT ReadOverlay();
  HRESULT ReadOverlayTable(unsigned streamIndex, const COverlayMap &map,
      unsigned level, UInt64 position, UInt64 virt,
      unsigned &items);
  HRESULT DecodeBlock(unsigned index);
  HRESULT OpenStructure(IInStream *stream, IArchiveOpenCallback *openCallback);
  HRESULT OpenContent(IArchiveOpenCallback *openCallback);
  HRESULT Open2(IInStream *stream, IArchiveOpenCallback *openCallback) Z7_override;
public:
  CHandler(): _phySize(0), _totalPhysicalSize(0), _firstPhysicalSize(0), _numVolumes(1),
      _maiChunkSize(0), _maiMaxChunks(0),
      _splitSize((UInt64)(Int64)-1),
      _sectorSize(512), _method(0), _version(0),
      _cacheIndex((unsigned)-1), _depth(0), _isMai(false), _smart(false), _dependent(false), _rawImage(false),
      _overlay(false), _growableMfi(false),
      _encryption(0), _protected(false) {}
  ~CHandler() { Close(); }
};

HRESULT CHandler::OpenVolumes(const Byte *header, IArchiveOpenCallback *openCallback)
{
  const UInt32 count = Read32(header + 60);
  const UInt64 total = Read64(header + 52), base = Read32(header + 24);
  MIRAY_CHECK(openCallback && count > 1 && count <= 1024
      && base + Read64(header + 28) == _phySize && total <= ((UInt64)1 << 60) - base)
  Z7_DECL_CMyComPtr_QI_FROM(IArchiveOpenVolumeCallback, callback, openCallback)
  MIRAY_CHECK(callback)
  NCOM::CPropVariant prop;
  RINOK(callback->GetProperty(kpidName, &prop))
  MIRAY_CHECK(prop.vt == VT_BSTR)
  const UString name = _sourceName.IsEmpty() ? UString(prop.bstrVal) : _sourceName;
  UString lower(name);
  lower.MakeLower_Ascii();
  MIRAY_CHECK(name.Len() > 6)
  const bool differentialName = StringsAreEqual_Ascii(lower.RightPtr(4), ".mfd");
  MIRAY_CHECK(differentialName || StringsAreEqual_Ascii(lower.RightPtr(4), ".mfi"))
  const unsigned end = name.Len() - 4;
  unsigned start = end;
  while (start && name[start - 1] >= L'0' && name[start - 1] <= L'9')
    start--;
  const unsigned width = end - start;
  MIRAY_CHECK(start && width > 0 && width <= 6 && name[start - 1] == L'.' && name[end - 1] == L'1')
  for (unsigned i = start; i + 1 < end; i++)
    MIRAY_CHECK(name[i] == L'0')
  CMyComPtr2<IInStream, CMultiStream> combined;
  combined.Create_if_Empty();
  CMultiStream::CSubStreamInfo first;
  first.Stream = Stream;
  first.Size = _phySize;
  RINOK(InStream_SeekSet(Stream, 0))
  combined->Streams.Add(first);
  UInt64 offset = Read64(header + 28);
  _splitSize = Read64(header + 68);
  _numVolumes = count;
  MIRAY_CHECK(_splitSize > 0)
  for (UInt32 index = 1; index < count; index++)
  {
    wchar_t digits[16];
    ConvertUInt32ToString(index + 1, digits);
    UString next = name.Left(start);
    const unsigned numDigits = (unsigned)wcslen(digits);
    for (unsigned i = numDigits; i < width; i++)
      next += L'0';
    next += digits;
    next += differentialName ? L".mfds" : L".mfis";
    CMyComPtr<IInStream> input;
    RINOK(callback->GetStream(next, &input))
    MIRAY_CHECK(input)
    UInt64 physical;
    RINOK(InStream_GetSize_SeekToEnd(input, physical))
    RINOK(InStream_SeekSet(input, 0))
    Byte h[112];
    RINOK(ReadStream_FALSE(input, h, sizeof(h)))
    MIRAY_CHECK(memcmp(h, header, 24) == 0 && memcmp(h + 36, header + 36, 16) == 0
        && CrcCalc(h, 108) == Read32(h + 108))
    const UInt64 dataBase = Read32(h + 24), length = Read64(h + 28);
    MIRAY_CHECK(dataBase >= sizeof(h) && length > 0 && dataBase <= physical
        && length == physical - dataBase && Read64(h + 76) == index
        && Read64(h + 84) == offset && Read64(h + 52) == 0
        && offset <= total && length <= total - offset
        && physical <= ((UInt64)1 << 60) - _totalPhysicalSize)
    CMyComPtr2<IInStream, CLimitedInStream> limited;
    limited.Create_if_Empty();
    limited->SetStream(input);
    RINOK(limited->InitAndSeek(dataBase, length))
    CMultiStream::CSubStreamInfo entry;
    entry.Stream = limited;
    entry.Size = length;
    combined->Streams.Add(entry);
    offset += length;
    _totalPhysicalSize += physical;
  }
  MIRAY_CHECK(offset == total)
  RINOK(combined->Init())
  Stream = combined;
  _phySize = base + total;
  return S_OK;
}

HRESULT CHandler::OpenMfi(IArchiveOpenCallback *openCallback)
{
  Byte h[112];
  RINOK(ReadAt(0, h, sizeof(h)))
  MIRAY_CHECK(memcmp(h, kMsfcSignature, sizeof(kMsfcSignature)) == 0
      && Read32(h + 20) == 1 && CrcCalc(h, 108) == Read32(h + 108))
  const UInt64 base = Read32(h + 24);
  UInt64 size = Read64(h + 28);
  MIRAY_CHECK(base >= sizeof(h) && base <= _phySize && size <= _phySize - base)
  MIRAY_CHECK(Read64(h + 76) == 0 && Read64(h + 84) == 0)
  if (size == 0 && Read64(h + 52) == 0)
  {
    MIRAY_CHECK(Read32(h + 60) == 1 && Read64(h + 68) == 0)
    _growableMfi = true;
    size = _phySize - base;
  }
  if (!_growableMfi && Read64(h + 52) != size)
  {
    MIRAY_CHECK(Read64(h + 52) > size)
    RINOK(OpenVolumes(h, openCallback))
    size = Read64(h + 52);
  }
  Byte m[80];
  RINOK(ReadAt(base, m, sizeof(m)))
  MIRAY_CHECK(memcmp(m, "MDSC", 4) == 0 && Read32(m + 4) == 80 && Read32(m + 24) == 1)
  const UInt64 chunk = Read64(m + 60);
  const UInt32 numChunks = Read32(m + 68);
  MIRAY_CHECK(chunk >= 512 && chunk <= kMetadataLimit && (chunk & (chunk - 1)) == 0
      && numChunks <= size / chunk)
  CByteBuffer first;
  first.Alloc((size_t)chunk);
  RINOK(ReadAt(base, first, first.Size()))
  CImageStream bootstrap;
  bootstrap.Name = "Stream0";
  UInt32 head = Read32(m + 72);
  CRecordVector<UInt32> visited;
  while (head)
  {
    MIRAY_CHECK(head >= 80 && head <= chunk - 60 && visited.Size() < 4096)
    FOR_VECTOR (i, visited)
      MIRAY_CHECK(visited[i] != head)
    visited.Add(head);
    const Byte *entry = first + head;
    if (memcmp(entry + 24, "Stream0", 7) == 0 && entry[31] == 0)
      break;
    head = Read32(entry);
  }
  MIRAY_CHECK(head != 0 && Read32(first + head + 4) == 60 && Read32(first + head + 8) == 2)
  bootstrap.Size = Read64(first + head + 16);
  MIRAY_CHECK(bootstrap.Size >= sizeof(m) && bootstrap.Size <= kMetadataLimit)
  const UInt64 directoryChunks = bootstrap.Size / chunk + (bootstrap.Size % chunk != 0);
  MIRAY_CHECK(directoryChunks <= numChunks)
  UInt64 directoryAdded = 0;
  UInt32 directoryExtra = Read32(first + head + 56);
  CByteBuffer used;
  used.Alloc((size_t)bootstrap.Size);
  memset(used, 0, used.Size());
  unsigned directoryLists = 0;
  while (directoryExtra)
  {
    MIRAY_CHECK(directoryExtra >= 80 && directoryExtra <= bootstrap.Size - 8
        && !used[directoryExtra] && directoryLists++ < kItemLimit)
    used[directoryExtra] = 1;
    Byte header[8];
    RINOK(ReadDirectoryData(bootstrap, base, chunk, directoryExtra, header, sizeof(header)))
    const UInt32 bytes = Read32(header + 4);
    MIRAY_CHECK(bytes >= 8 && bytes % 4 == 0 && bytes <= bootstrap.Size - directoryExtra)
    for (UInt32 j = 8; j < bytes && directoryAdded < directoryChunks; j += 4, directoryAdded++)
    {
      Byte word[4];
      RINOK(ReadDirectoryData(bootstrap, base, chunk, directoryExtra + j, word, sizeof(word)))
      const UInt32 index = Read32(word);
      MIRAY_CHECK(index < numChunks)
      AddChunkExtent(bootstrap, base + (UInt64)index * chunk, chunk);
    }
    directoryExtra = Read32(header);
  }
  MIRAY_CHECK(directoryAdded == directoryChunks)
  RINOK(CheckStream(bootstrap))
  CByteBuffer dir;
  dir.Alloc((size_t)bootstrap.Size);
  RINOK(ReadData(bootstrap, 0, dir, dir.Size()))
  MIRAY_CHECK(memcmp(dir, m, sizeof(m)) == 0)
  memset(used, 0, used.Size());
  UInt32 offset = Read32(m + 72);
  while (offset)
  {
    MIRAY_CHECK(offset >= 80 && offset <= dir.Size() - 60 && !used[offset] && _streams.Size() < 4096)
    used[offset] = 1;
    const Byte *p = dir + offset;
    const UInt32 kind = Read32(p + 8);
    MIRAY_CHECK(Read32(p + 4) == 60 && (kind == 0 || kind == 2))
    CImageStream &s = _streams.AddNew();
    s.Name.SetFrom((const char *)p + 24, 32);
    const int nul = s.Name.Find((char)0);
    if (nul >= 0)
      s.Name.DeleteFrom((unsigned)nul);
    s.Size = Read64(p + 16);
    if (kind == 0)
    {
      const UInt32 extra = Read32(p + 56);
      MIRAY_CHECK(extra >= 80 && extra <= dir.Size() - 8 && Read32(dir + extra) == 0
          && s.Size <= dir.Size() - extra - 8)
      UInt64 position = (UInt64)extra + 8;
      UInt64 remaining = s.Size;
      FOR_VECTOR (i, bootstrap.Extents)
      {
        const CExtent &source = bootstrap.Extents[i];
        if (position >= source.Size)
        {
          position -= source.Size;
          continue;
        }
        const UInt64 take = remaining < source.Size - position ? remaining : source.Size - position;
        CExtent e;
        e.Offset = source.Offset + position;
        e.Size = take;
        s.Extents.Add(e);
        remaining -= take;
        if (!remaining)
          break;
        position = 0;
      }
      MIRAY_CHECK(remaining == 0)
      RINOK(CheckStream(s))
      offset = Read32(p);
      continue;
    }
    const UInt64 needed = s.Size / chunk + (s.Size % chunk != 0);
    MIRAY_CHECK(needed <= numChunks && needed <= kItemLimit)
    UInt32 extra = Read32(p + 56);
    UInt64 added = 0;
    while (extra)
    {
      MIRAY_CHECK(extra >= 80 && extra <= dir.Size() - 8 && !used[extra])
      used[extra] = 1;
      const UInt32 bytes = Read32(dir + extra + 4);
      MIRAY_CHECK(bytes >= 8 && bytes % 4 == 0 && bytes <= dir.Size() - extra)
      for (UInt32 j = 8; j < bytes && added < needed; j += 4, added++)
      {
        const UInt32 c = Read32(dir + extra + j);
        MIRAY_CHECK(c < numChunks)
        AddChunkExtent(s, base + (UInt64)c * chunk, chunk);
      }
      extra = Read32(dir + extra);
    }
    MIRAY_CHECK(added == needed)
    RINOK(CheckStream(s))
    offset = Read32(p);
  }
  unsigned directoryIndex = 0;
  for (; directoryIndex < _streams.Size(); directoryIndex++)
    if (_streams[directoryIndex].Name == "Stream0")
      break;
  MIRAY_CHECK(directoryIndex < _streams.Size())
  const CImageStream &directoryStream = _streams[directoryIndex];
  MIRAY_CHECK(directoryStream.Size == bootstrap.Size)
  CByteBuffer checkedDirectory;
  checkedDirectory.Alloc((size_t)directoryStream.Size);
  RINOK(ReadData(directoryStream, 0, checkedDirectory, checkedDirectory.Size()))
  MIRAY_CHECK(memcmp(checkedDirectory, dir, dir.Size()) == 0)
  SetUi32(checkedDirectory + 76, 0);
  MIRAY_CHECK(CrcCalc(checkedDirectory, checkedDirectory.Size()) == Read32(m + 76))
  return S_OK;
}

HRESULT CHandler::OpenMaiVolumes(const Byte *header, const Byte *footer, IArchiveOpenCallback *openCallback)
{
  const UInt32 count = Read32(header + 32);
  const UInt32 rootChunk = Read32(header + 36);
  const UInt32 rootChunks = Read32(footer + 52);
  MIRAY_CHECK(count > 0 && count <= 1024 && rootChunks > 0
      && (UInt64)rootChunks * _maiChunkSize == _phySize - 8192)
  if (count == 1)
  {
    MIRAY_CHECK(rootChunk == 0)
    return S_OK;
  }
  MIRAY_CHECK(openCallback && _maiMaxChunks != (UInt32)-1)
  Z7_DECL_CMyComPtr_QI_FROM(IArchiveOpenVolumeCallback, callback, openCallback)
  MIRAY_CHECK(callback)
  NCOM::CPropVariant prop;
  RINOK(callback->GetProperty(kpidName, &prop))
  MIRAY_CHECK(prop.vt == VT_BSTR)
  const UString name = _sourceName.IsEmpty() ? UString(prop.bstrVal) : _sourceName;
  UString lower(name);
  lower.MakeLower_Ascii();
  MIRAY_CHECK(name.Len() > 4 && (StringsAreEqual_Ascii(lower.RightPtr(4), ".mai")
      || StringsAreEqual_Ascii(lower.RightPtr(4), ".mfd")))
  const UString stem = name.Left(name.Len() - 4);
  CMyComPtr<IInStream> root = Stream;
  CMyComPtr2<IInStream, CMultiStream> combined;
  combined.Create_if_Empty();
  AddVolumeRecord(combined.ClsPtr(), header);
  UInt64 chunks = 0;
  unsigned width = 0;
  for (UInt32 index = 1; index < count; index++)
  {
    CMyComPtr<IInStream> input;
    wchar_t digits[16];
    ConvertUInt32ToString(index, digits);
    const unsigned numDigits = (unsigned)wcslen(digits);
    const unsigned widths[] = { 3, 1, 2, 4, 5, 6 };
    for (unsigned attempt = 0; attempt < Z7_ARRAY_SIZE(widths); attempt++)
    {
      const unsigned candidate = width ? width : widths[attempt];
      UString next = stem;
      next += L'.';
      for (unsigned j = numDigits; j < candidate; j++)
        next += L'0';
      next += digits;
      next += L".mais";
      const HRESULT result = callback->GetStream(next, &input);
      if (result == S_OK && input)
      {
        width = candidate;
        break;
      }
      input.Release();
      if (width)
        break;
    }
    MIRAY_CHECK(input)
    UInt64 physical;
    RINOK(InStream_GetSize_SeekToEnd(input, physical))
    MIRAY_CHECK(physical >= 8192)
    Byte h[4096], f[4096];
    RINOK(InStream_SeekSet(input, 0))
    RINOK(ReadStream_FALSE(input, h, sizeof(h)))
    RINOK(InStream_SeekSet(input, physical - sizeof(f)))
    RINOK(ReadStream_FALSE(input, f, sizeof(f)))
    CByteBuffer record;
    record.CopyFrom(h, sizeof(h));
    MIRAY_CHECK(CheckZeroCrc(record) && memcmp(h, "XSAM", 4) == 0
        && Read32(h + 4) == 4096 && Read32(h + 12) == 1
        && memcmp(h + 16, header + 16, 16) == 0
        && Read32(h + 32) == index && Read32(h + 36) == chunks
        && memcmp(h + 40, header + 40, 16) == 0)
    record.CopyFrom(f, sizeof(f));
    MIRAY_CHECK(CheckZeroCrc(record) && memcmp(f, "NSAM", 4) == 0
        && Read32(f + 4) == 4096 && memcmp(f + 12, h + 12, 40) == 0)
    const UInt32 length = Read32(f + 52);
    MIRAY_CHECK(length > 0 && length <= _maiMaxChunks
        && (UInt64)length * _maiChunkSize == physical - 8192
        && chunks <= rootChunk && length <= rootChunk - chunks
        && physical <= ((UInt64)1 << 60) - _totalPhysicalSize)
    const UInt64 descriptorPos = Read64(f + 56), descriptorSize = Read64(f + 64);
    MIRAY_CHECK(descriptorPos >= 4096 && descriptorPos <= physical - 4096
        && descriptorSize >= 44 && descriptorSize <= kMetadataLimit
        && descriptorSize <= physical - 4096 - descriptorPos)
    record.Alloc((size_t)descriptorSize);
    RINOK(InStream_SeekSet(input, descriptorPos))
    RINOK(ReadStream_FALSE(input, record, record.Size()))
    MIRAY_CHECK(memcmp(record, "DSAM", 4) == 0 && Read32(record + 4) == descriptorSize
        && (Read32(record + 12) == 1 || Read32(record + 12) == 2) && CheckZeroCrc(record))
    RINOK(AddVolumeRange(combined.ClsPtr(), input, 4096, physical - 8192))
    CExtent volume;
    volume.Offset = chunks;
    volume.Size = length;
    _maiVolumes.Add(volume);
    CByteBuffer &physicalRecords = _maiVolumeRecords.AddNew();
    physicalRecords.Alloc(8192);
    memcpy(physicalRecords, h, sizeof(h));
    memcpy(physicalRecords + 4096, f, sizeof(f));
    chunks += length;
    _totalPhysicalSize += physical;
  }
  MIRAY_CHECK(chunks == rootChunk)
  RINOK(AddVolumeRange(combined.ClsPtr(), root, 4096, _phySize - 8192))
  AddVolumeRecord(combined.ClsPtr(), footer);
  RINOK(combined->Init())
  Stream = combined;
  _phySize = 8192 + (chunks + rootChunks) * _maiChunkSize;
  _numVolumes = count;
  return S_OK;
}

HRESULT CHandler::OpenMai(IArchiveOpenCallback *openCallback)
{
  CByteBuffer h, f;
  h.Alloc(4096);
  f.Alloc(4096);
  RINOK(ReadAt(0, h, h.Size()))
  MIRAY_CHECK(Read32(h + 4) == 4096 && Read32(h + 12) == 1 && CheckZeroCrc(h))
  const UInt32 chunk = Read32(h + 44);
  _maiChunkSize = chunk;
  _maiMaxChunks = Read32(h + 40);
  MIRAY_CHECK(chunk >= 512 && chunk <= kMetadataLimit && (chunk & (chunk - 1)) == 0
      && Read32(h + 48) == 4096 && Read32(h + 52) == 4096 && _phySize >= 8192)
  RINOK(ReadAt(_phySize - 4096, f, f.Size()))
  MIRAY_CHECK(memcmp(f, "FSAM", 4) == 0 && memcmp(f + 12, h + 12, 40) == 0 && CheckZeroCrc(f))
  MIRAY_CHECK(Read64(f + 56) >= 4096 && Read64(f + 56) <= _phySize - 4096
      && Read64(f + 64) <= _phySize - 4096 - Read64(f + 56))
  RINOK(OpenMaiVolumes(h, f, openCallback))
  const UInt64 descriptorPos = Read64(f + 56) + (UInt64)Read32(h + 36) * chunk;
  const UInt64 descriptorSize = Read64(f + 64);
  MIRAY_CHECK(descriptorSize >= 44 && descriptorSize <= kMetadataLimit
      && descriptorPos >= 4096 && descriptorPos <= _phySize - 4096
      && descriptorSize <= _phySize - 4096 - descriptorPos)
  CByteBuffer d;
  d.Alloc((size_t)descriptorSize);
  RINOK(ReadAt(descriptorPos, d, d.Size()))
  MIRAY_CHECK(memcmp(d, "DSAM", 4) == 0 && Read32(d + 4) == descriptorSize
      && Read32(d + 12) == 1 && CheckZeroCrc(d))
  const UInt32 table = Read32(d + 16), tableSize = Read32(d + 20);
  MIRAY_CHECK(table >= 44 && table <= descriptorSize && tableSize >= 4
      && tableSize <= descriptorSize - table)
  const UInt32 volumeTable = Read32(d + 24), volumeTableSize = Read32(d + 28);
  if (_numVolumes > 1)
  {
    MIRAY_CHECK(volumeTable >= 44 && volumeTable <= descriptorSize
        && volumeTableSize <= descriptorSize - volumeTable
        && volumeTableSize == 4 + (_numVolumes - 1) * 16
        && Read32(d + volumeTable) == _maiVolumes.Size())
    FOR_VECTOR (i, _maiVolumes)
    {
      const Byte *entry = d + volumeTable + 4 + i * 16;
      MIRAY_CHECK(Read32(entry) == _maiVolumes[i].Offset
          && Read32(entry + 4) == _maiVolumes[i].Size)
      RINOK(ReadMaiChecksums(d, Read32(entry + 8), Read32(entry + 12), i, true))
    }
  }
  else
    MIRAY_CHECK(volumeTable == 0 && volumeTableSize == 0)
  const UInt32 count = Read32(d + table);
  MIRAY_CHECK(count > 0 && count <= 4096 && (UInt64)count * 72 + 4 == tableSize)
  for (UInt32 i = 0; i < count; i++)
  {
    const Byte *p = d + table + 4 + i * 72;
    CImageStream &s = _streams.AddNew();
    s.Name.SetFrom((const char *)p, 32);
    const int nul = s.Name.Find((char)0);
    if (nul >= 0)
      s.Name.DeleteFrom((unsigned)nul);
    s.Size = Read64(p + 40);
    const UInt32 flags = Read32(p + 36);
    MIRAY_CHECK(flags == 0 || flags == 3 || flags == 4)
    const UInt32 inlinePos = Read32(p + 48), inlineSize = Read32(p + 52);
    if (inlineSize)
    {
      MIRAY_CHECK(s.Size == inlineSize && inlinePos <= descriptorSize && inlineSize <= descriptorSize - inlinePos)
      CExtent e;
      e.Offset = descriptorPos + inlinePos;
      e.Size = inlineSize;
      s.Extents.Add(e);
    }
    else
    {
      const UInt32 runs = Read32(p + 56), runsSize = Read32(p + 60);
      MIRAY_CHECK(runsSize % 8 == 0 && runs <= descriptorSize && runsSize <= descriptorSize - runs)
      for (UInt32 j = 0; j < runsSize; j += 8)
      {
        CExtent e;
        e.Offset = 4096 + (UInt64)Read32(d + runs + j) * chunk;
        e.Size = (UInt64)Read32(d + runs + j + 4) * chunk;
        MIRAY_CHECK(e.Offset <= descriptorPos && e.Size <= descriptorPos - e.Offset)
        s.Extents.Add(e);
      }
    }
    RINOK(CheckStream(s))
    RINOK(ReadMaiChecksums(d, Read32(p + 64), Read32(p + 68), i))
  }
  return S_OK;
}

HRESULT CHandler::ReadMaiChecksums(const CByteBuffer &descriptor, UInt32 offset, UInt32 size,
    unsigned streamIndex, bool physical)
{
  if (!size)
  {
    MIRAY_CHECK(offset == 0)
    return S_OK;
  }
  MIRAY_CHECK(offset >= 44 && offset <= descriptor.Size() && size <= descriptor.Size() - offset)
  const Byte *p = descriptor + offset;
  size_t position = 0;
  unsigned seen = 0;
  while (size - position >= 4)
  {
    const unsigned length = Read16(p + position), type = Read16(p + position + 2);
    position += 4;
    if (!length && !type)
    {
      for (; position < size; position++)
        MIRAY_CHECK(p[position] == 0)
      return S_OK;
    }
    const unsigned method = type == 2 ? 0 : type == 3 ? 1 : type == 4 ? 2 : type == 6 ? 3 : 4;
    MIRAY_CHECK(method < Z7_ARRAY_SIZE(kDigestSizes) && length == kDigestSizes[method]
        && length <= size - position && !(seen & (1 << method)))
    seen |= 1 << method;
    CImageChecksum item;
    item.StreamIndex = streamIndex;
    item.Method = method;
    item.Physical = physical;
    memset(item.Digest, 0, sizeof(item.Digest));
    memcpy(item.Digest, p + position, length);
    _maiChecksums.Add(item);
    position += length;
  }
  return S_FALSE;
}

HRESULT CHandler::VerifyMaiChecksums()
{
  if (_maiChecksums.IsEmpty())
    return S_OK;
  static const CMethodId methods[] = { 0x208, 0x201, 0xA, 0x231 };
  CByteBuffer buffer;
  buffer.Alloc(1 << 20);
  for (unsigned unit = 0; unit < _streams.Size() + _maiVolumes.Size(); unit++)
  {
    const bool physical = unit >= _streams.Size();
    const unsigned streamIndex = physical ? unit - _streams.Size() : unit;
    CMyComPtr<IHasher> hashers[4];
    bool needed = false;
    FOR_VECTOR (i, _maiChecksums)
      if (_maiChecksums[i].Physical == physical && _maiChecksums[i].StreamIndex == streamIndex)
      {
        const unsigned method = _maiChecksums[i].Method;
        AString name;
        RINOK(CreateHasher(
          #ifdef Z7_EXTERNAL_CODECS
          NULL,
          #endif
          methods[method], name, hashers[method]))
        MIRAY_CHECK(hashers[method])
        hashers[method]->Init();
        if (physical)
          hashers[method]->Update(_maiVolumeRecords[streamIndex], 4096);
        needed = true;
      }
    if (!needed)
      continue;
    const UInt64 size = physical ? _maiVolumes[streamIndex].Size * _maiChunkSize : _streams[streamIndex].Size;
    for (UInt64 offset = 0; offset < size;)
    {
      const UInt32 take = size - offset < buffer.Size() ? (UInt32)(size - offset) : (UInt32)buffer.Size();
      if (physical)
        RINOK(ReadAt(4096 + _maiVolumes[streamIndex].Offset * _maiChunkSize + offset, buffer, take))
      else
        RINOK(ReadData(_streams[streamIndex], offset, buffer, take))
      for (unsigned method = 0; method < Z7_ARRAY_SIZE(hashers); method++)
        if (hashers[method])
          hashers[method]->Update(buffer, take);
      offset += take;
    }
    FOR_VECTOR (i, _maiChecksums)
      if (_maiChecksums[i].Physical == physical && _maiChecksums[i].StreamIndex == streamIndex)
      {
        Byte digest[32];
        const unsigned method = _maiChecksums[i].Method;
        if (physical)
          hashers[method]->Update(_maiVolumeRecords[streamIndex] + 4096, 4096);
        hashers[method]->Final(digest);
        MIRAY_CHECK(memcmp(digest, _maiChecksums[i].Digest, kDigestSizes[method]) == 0)
      }
  }
  return S_OK;
}

HRESULT CHandler::ReadMetadata()
{
  unsigned index = 0;
  for (; index < _streams.Size(); index++)
    if (_streams[index].Name == "mfic.img")
      break;
  if (index == _streams.Size())
  {
    for (index = 0; index < _streams.Size(); index++)
      if (_streams[index].Name == "meta.ovl")
        break;
    _overlay = index < _streams.Size();
  }
  MIRAY_CHECK(index < _streams.Size() && (!_growableMfi || _overlay))
  const CImageStream &s = _streams[index];
  MIRAY_CHECK(s.Size >= 24 && s.Size <= kMetadataLimit)
  CByteBuffer data;
  data.Alloc((size_t)s.Size);
  RINOK(ReadData(s, 0, data, data.Size()))
  _version = Read32(data + 4);
  MIRAY_CHECK(memcmp(data, "MFIC", 4) == 0 && (_version == 2 || _version == 3 || _version == 4)
      && Read32(data + 8) == 0 && Read32(data + 16) == 4 && Read32(data + 20) == 1)
  UInt64 sectors = 0;
  UInt64 imageType = 0, splitSize = (UInt64)(Int64)-1;
  CRecordVector<UInt32> globalSeen, partSeen;
  Sha256_Init(&_keyPrefixHash);
  size_t pos = 24;
  unsigned properties = 0;
  while (pos < data.Size())
  {
    MIRAY_CHECK(data.Size() - pos >= 8 && properties++ < 4096)
    const UInt32 key = Read32(data + pos) & 0x7fffffff;
    const UInt32 size = Read32(data + pos + 4);
    pos += 8;
    MIRAY_CHECK(size <= data.Size() - pos && !(key >= 0x1100 && key < 0x2000))
    const Byte *p = data + pos;
    bool regionExtra = false;
    if (key == 0x2000 && size)
    {
      MIRAY_CHECK(size >= 4)
      const UInt32 count = Read32(p);
      MIRAY_CHECK(count > 0 && count <= 4096)
      UInt32 offset = 4;
      for (UInt32 i = 0; i < count; i++)
      {
        MIRAY_CHECK(size - offset >= 8)
        const UInt32 length = Read32(p + offset + 4);
        MIRAY_CHECK(length <= size - offset - 8)
        if (memcmp(p + offset, "ELST", 4) == 0
            || memcmp(p + offset, "MLST", 4) == 0 || memcmp(p + offset, "SLST", 4) == 0)
          regionExtra = true;
        offset += 8 + length;
      }
      MIRAY_CHECK(offset == size)
    }
    if (key == 5)
    {
      MIRAY_CHECK(size == 0 && _parts.Size() < 4096)
      _parts.AddNew();
      partSeen.Clear();
    }
    else
    {
      const bool isPart = (key >= 0x1000 && key < 0x2000) || regionExtra;
      MIRAY_CHECK(!isPart || !_parts.IsEmpty())
      CRecordVector<UInt32> &seen = isPart ? partSeen : globalSeen;
      FOR_VECTOR (i, seen)
        MIRAY_CHECK(seen[i] != key)
      seen.Add(key);
      if (isPart)
      {
        HashKeyData(&_keyPrefixHash, data + pos - 8, (size_t)size + 8);
        CPart &part = _parts.Back();
        if (regionExtra)
        {
          UInt32 offset = 4;
          for (UInt32 i = 0; i < Read32(p); i++)
          {
            const UInt32 length = Read32(p + offset + 4);
            MIRAY_CHECK(memcmp(p + offset, "ELST", 4) == 0 && length >= 8)
            const Byte *list = p + offset + 8;
            const UInt32 count = Read32(list + 4);
            MIRAY_CHECK(Read32(list) == 1 && count <= kItemLimit
                && (UInt64)8 + (UInt64)count * 16 == length
                && part.Errors.Size() <= kItemLimit - count)
            for (UInt32 j = 0; j < count; j++)
            {
              CExtent error;
              error.Offset = Read64(list + 8 + (size_t)j * 16);
              error.Size = Read64(list + 16 + (size_t)j * 16);
              MIRAY_CHECK(error.Size > 0 && error.Offset <= (UInt64)-1 - error.Size
                  && (part.Errors.IsEmpty() || error.Offset >= part.Errors.Back().Offset + part.Errors.Back().Size))
              part.Errors.Add(error);
            }
            offset += 8 + length;
          }
        }
        else if (key == 0x1000)
        {
          MIRAY_CHECK(size > 0 && size <= 32)
          part.Name.SetFrom((const char *)p, size);
        }
        else if (key == 0x100c)
        {
          MIRAY_CHECK(size == LZMA_PROPS_SIZE)
          memcpy(part.LzmaProps, p, LZMA_PROPS_SIZE);
          part.HasLzmaProps = true;
        }
        else if (key == 0x1001 || key == 0x1002 || key == 0x1003 || key == 0x1004
            || key == 0x1007 || key == 0x100a || key == 0x100b)
        {
          MIRAY_CHECK(size == 0 || size == 4 || size == 8)
          const UInt64 value = size == 8 ? Read64(p) : size == 4 ? Read32(p) : 0;
          switch (key)
          {
            case 0x1001: part.Base = value; break;
            case 0x1002: part.StoredBytes = value; part.HasStoredBytes = true; break;
            case 0x1003: part.Stored = value; break;
            case 0x1004: part.Last = value; part.HasLast = true; break;
            case 0x1007: MIRAY_CHECK(value <= 5 || value == 8 || value == 9) part.Kind = (UInt32)value; break;
            case 0x100a: part.Sectors = value; break;
            case 0x100b: MIRAY_CHECK(value <= 3) part.Method = (UInt32)value; break;
          }
        }
      }
      else if (key == 13 || key == 14)
      {
        MIRAY_CHECK(size == 16)
        CByteBuffer &dest = key == 13 ? _imageId : _baseId;
        dest.CopyFrom(p, size);
      }
      else if (key == 26)
      {
        MIRAY_CHECK(size > 0 && size <= 4096)
        for (UInt32 i = 0; i < size; i++)
          MIRAY_CHECK(p[i] != 0)
        AString encoded;
        encoded.SetFrom((const char *)p, size);
        UString path;
        MIRAY_CHECK(ConvertUTF8ToUnicode(encoded, path))
        unsigned start = 0;
        for (unsigned i = 0; i < path.Len(); i++)
          if (path[i] == L'/' || path[i] == L'\\')
            start = i + 1;
        _parentName = path;
        _parentName.DeleteFrontal(start);
        MIRAY_CHECK(!_parentName.IsEmpty() && _parentName != L"." && _parentName != L".."
            && _parentName.Find(L':') < 0)
      }
      else if (key == 8 || key == 9 || key == 0x2000)
      {
        MIRAY_CHECK(key == 0x2000 || size == 0 || size == SHA256_DIGEST_SIZE)
        CByteBuffer &dest = key == 8 ? _verifier : key == 9 ? _salt : _keyStore;
        dest.CopyFrom(p, size);
      }
      else if (key == 6 || key == 11 || key == 12 || key == 15 || key == 17)
      {
        MIRAY_CHECK(size == 4 || size == 8)
        const UInt64 value = size == 8 ? Read64(p) : Read32(p);
        if (key == 6)
        {
          MIRAY_CHECK(value == 512 || value == 4096)
          _sectorSize = (UInt32)value;
        }
        else if (key == 11)
        {
          MIRAY_CHECK(value <= 2)
          _encryption = (UInt32)value;
        }
        else if (key == 12)
          sectors = value;
        else if (key == 15)
          splitSize = value;
        else
          imageType = value;
      }
    }
    pos += size;
  }
  _protected = _verifier.Size() != 0 || _salt.Size() != 0 || _encryption != 0;
  MIRAY_CHECK(!_protected || (_verifier.Size() == SHA256_DIGEST_SIZE && _salt.Size() == SHA256_DIGEST_SIZE))
  MIRAY_CHECK(!_parts.IsEmpty() && sectors > 0 && sectors <= ((UInt64)1 << 60) / _sectorSize)
  const UInt64 fullType = _isMai ? 24 : 8;
  _size = sectors * _sectorSize;
  if (_overlay)
  {
    MIRAY_CHECK(!_isMai && _version == 4 && imageType == 21 && _numVolumes == 1
        && splitSize == 0 && _parts.Size() == 1 && _encryption == 0)
    CPart &part = _parts[0];
    MIRAY_CHECK(part.Kind == 9 && part.Base == (UInt64)-1 && part.Stored == 0
        && part.Sectors == sectors && part.Method == 0 && part.Name == "_overlay"
        && part.Errors.IsEmpty() && (!part.HasLast || part.Last == 0)
        && (!part.HasStoredBytes || part.StoredBytes == 0))
    _splitSize = 0;
    return S_OK;
  }
  _dependent = imageType == 14;
  // Observed BitImage FullImage types use a whole-disk region: MFI=20, MAI=28.
  _rawImage = !_isMai && imageType == 10;
  const bool bitImage = _rawImage || imageType == (_isMai ? 28 : 20);
  MIRAY_CHECK(bitImage || _dependent || imageType == fullType || imageType == fullType + 1)
  if (_dependent && splitSize == 0)
  {
    if (_numVolumes == 1)
      _splitSize = 0;
  }
  else if (_isMai && _maiMaxChunks != (UInt32)-1)
  {
    MIRAY_CHECK(splitSize >= 8192 && splitSize != (UInt64)(Int64)-1
        && (splitSize - 8192) / _maiChunkSize == _maiMaxChunks)
    _splitSize = splitSize;
  }
  else
    MIRAY_CHECK(splitSize == _splitSize)
  _smart = imageType == fullType + 1;
  MIRAY_CHECK(!_rawImage || (_parts.Size() == 1 && _parts[0].Kind == 4
      && _parts[0].Method == 0 && _parts[0].Name == "data"))
  UInt64 next = 0;
  FOR_VECTOR (i, _parts)
  {
    CPart &part = _parts[i];
    MIRAY_CHECK(part.Base >= next && (_smart || _dependent || part.Base == next)
        && part.Sectors > 0 && part.Stored <= part.Sectors
        && part.Base <= sectors && part.Sectors <= sectors - part.Base
        && (_dependent ? part.Kind == 8 : part.Kind <= 5))
    UInt64 errorSectors = 0;
    FOR_VECTOR (j, part.Errors)
    {
      const CExtent &error = part.Errors[j];
      MIRAY_CHECK(error.Offset <= part.Sectors && error.Size <= part.Sectors - error.Offset)
      CExtent range;
      range.Offset = (part.Base + error.Offset) * _sectorSize;
      range.Size = error.Size * _sectorSize;
      _unavailable.Add(range);
      errorSectors += error.Size;
    }
    MIRAY_CHECK((_smart || _dependent || part.Stored + errorSectors >= part.Sectors)
        && (!_rawImage || part.Stored == part.Sectors))
    if (part.Method == 3)
      MIRAY_CHECK(part.HasLzmaProps && part.LzmaProps[0] < 225
          && Read32(part.LzmaProps + 1) >= 4096 && Read32(part.LzmaProps + 1) <= kBlockLimit)
    for (part.StreamIndex = 0; part.StreamIndex < _streams.Size(); part.StreamIndex++)
      if (_streams[part.StreamIndex].Name == part.Name)
        break;
    MIRAY_CHECK(part.StreamIndex < _streams.Size())
    MIRAY_CHECK(!part.HasStoredBytes || part.StoredBytes == _streams[part.StreamIndex].Size)
    next = part.Base + part.Sectors;
    if (i == 0)
      _method = part.Method;
    else if (_method != part.Method)
      _method = 4;
  }
  MIRAY_CHECK(_smart || _dependent || next == sectors)
  return S_OK;
}

HRESULT CHandler::OpenBase(IArchiveOpenCallback *openCallback)
{
  if (!_dependent && !_overlay)
    return S_OK;
  MIRAY_CHECK(_depth < 15 && _imageId.Size() == 16 && _baseId.Size() == 16
      && memcmp(_imageId, _baseId, 16) != 0 && openCallback)
  Z7_DECL_CMyComPtr_QI_FROM(IArchiveOpenVolumeCallback, callback, openCallback)
  MIRAY_CHECK(callback)
  UStringVector candidates;
  if (!_parentName.IsEmpty())
    candidates.Add(_parentName);
  else
  {
    MIRAY_CHECK(_overlay)
    NCOM::CPropVariant prop;
    RINOK(callback->GetProperty(kpidName, &prop))
    MIRAY_CHECK(prop.vt == VT_BSTR)
    const UString name = _sourceName.IsEmpty() ? UString(prop.bstrVal) : _sourceName;
    UString lower(name);
    lower.MakeLower_Ascii();
    MIRAY_CHECK(name.Len() > 4 && StringsAreEqual_Ascii(lower.RightPtr(4), ".mfo"))
    static const wchar_t * const suffixes[] = { L".mfi", L".mai", L".mfd", L".001.mfi", L".001.mfd" };
    for (unsigned i = 0; i < Z7_ARRAY_SIZE(suffixes); i++)
    {
      UString next = name.Left(name.Len() - 4);
      next += suffixes[i];
      candidates.Add(next);
    }
  }
  FOR_VECTOR (candidate, candidates)
  {
    CMyComPtr<IInStream> input;
    const HRESULT result = callback->GetStream(candidates[candidate], &input);
    if (result == S_FALSE || (result == S_OK && !input))
      continue;
    RINOK(result)
    CHandler *parent = new CHandler;
    CMyComPtr<IInStream> owner = parent;
    parent->_sourceName = candidates[candidate];
    parent->_depth = _depth + 1;
    const HRESULT structure = parent->OpenStructure(input, openCallback);
    if (structure == S_FALSE && _overlay)
      continue;
    RINOK(structure)
    if (parent->_imageId.Size() != 16 || memcmp(parent->_imageId, _baseId, 16) != 0)
      continue;
    MIRAY_CHECK(parent->_size == _size && parent->_sectorSize == _sectorSize)
    if (!_overlay)
    {
      MIRAY_CHECK(parent->_parts.Size() == _parts.Size())
      FOR_VECTOR (i, _parts)
        MIRAY_CHECK(_parts[i].Name == parent->_parts[i].Name && _parts[i].Base == parent->_parts[i].Base
            && _parts[i].Sectors == parent->_parts[i].Sectors)
    }
    RINOK(parent->OpenContent(openCallback))
    if (_overlay && parent->_protected)
      _protected = true;
    _base = owner;
    return S_OK;
  }
  return S_FALSE;
}

HRESULT CHandler::ReadKeyStore(CRecordVector<UInt32> &offsets)
{
  const Byte *p = _keyStore;
  const size_t size = _keyStore.Size();
  MIRAY_CHECK(size >= 4)
  const UInt32 chunks = Read32(p);
  MIRAY_CHECK(chunks > 0 && chunks <= 4096)
  size_t position = 4;
  bool seen = false;
  for (UInt32 chunk = 0; chunk < chunks; chunk++)
  {
    MIRAY_CHECK(size - position >= 8)
    const UInt32 length = Read32(p + position + 4);
    MIRAY_CHECK(length <= size - position - 8)
    const size_t end = position + 8 + length;
    if (memcmp(p + position, "KSTO", 4) == 0)
    {
      MIRAY_CHECK(!seen && length >= 8 && Read32(p + position + 8) == 1)
      seen = true;
      const UInt32 count = Read32(p + position + 12);
      MIRAY_CHECK(count > 0 && count <= 4096)
      position += 16;
      for (UInt32 entry = 0; entry < count; entry++)
      {
        MIRAY_CHECK(end - position >= 8)
        const UInt32 entrySize = Read32(p + position), headerSize = Read32(p + position + 4);
        MIRAY_CHECK(entrySize >= 8 && entrySize <= end - position
            && headerSize >= 8 && headerSize <= entrySize)
        const Byte *wrapKey = headerSize >= 20 ? GetImageWrapKey(Read32(p + position + 12)) : NULL;
        if (wrapKey
            && Read32(p + position + 16) == (_encryption ? 5 : 0))
        {
          const unsigned keySize = _encryption == 0 ? 0 : _encryption == 1 ? 16 : 32;
          MIRAY_CHECK(headerSize == 40 && entrySize >= 40 + keySize + 32
              && Read32(p + position + 8) == 0 && Read32(p + position + 20) == keySize
              && Read32(p + position + 24) == (_protected ? 2 : 0) && Read32(p + position + 28) == 0
              && Read32(p + position + 32) == 0
              && (UInt64)40 + keySize + Read32(p + position + 36) + 32 == entrySize)
          CSha256 hash = _keyPrefixHash;
          Byte expected[SHA256_DIGEST_SIZE];
          HashKeyData(&hash, p + position, entrySize - SHA256_DIGEST_SIZE);
          Sha256_Final(&hash, expected);
          CByteBuffer trailer;
          trailer.CopyFrom(p + position + entrySize - SHA256_DIGEST_SIZE, SHA256_DIGEST_SIZE);
          DecryptEcb(trailer, trailer.Size(), wrapKey, 32);
          MIRAY_CHECK(memcmp(trailer, expected, sizeof(expected)) == 0)
          offsets.Add((UInt32)position + 40);
        }
        position += entrySize;
      }
      MIRAY_CHECK(position == end)
    }
    position = end;
  }
  MIRAY_CHECK(position == size && !offsets.IsEmpty())
  return S_OK;
}

HRESULT CHandler::Unlock(IArchiveOpenCallback *openCallback)
{
  unsigned keySize = 0;
  CRecordVector<UInt32> keyOffsets;
  if (_keyStore.Size() || _encryption)
    RINOK(ReadKeyStore(keyOffsets))
  if (!_protected)
    return S_OK;
  if (_encryption)
    keySize = _encryption == 1 ? 16 : 32;
  CMyComPtr<ICryptoGetTextPassword> callback;
  if (openCallback)
    openCallback->QueryInterface(IID_ICryptoGetTextPassword, (void **)&callback);
  if (!callback)
    return E_NOTIMPL;
  CMyComBSTR_Wipe password;
  RINOK(callback->CryptoGetTextPassword(&password))
  UString_Wipe unicode;
  if (password)
    unicode.SetFromBstr(password);
  AString_Wipe utf8;
  ConvertUnicodeToUTF8(unicode, utf8);
  Byte digest[SHA256_DIGEST_SIZE], passwordKey[SHA256_DIGEST_SIZE];
  HashPassword((const Byte *)utf8.Ptr(), utf8.Len(), NULL, digest);
  HashPassword(digest, sizeof(digest), _salt, passwordKey);
  HashPassword(passwordKey, sizeof(passwordKey), _salt, digest);
  unsigned difference = 0;
  for (unsigned i = 0; i < sizeof(digest); i++)
    difference |= digest[i] ^ _verifier[i];
  bool keysAgree = true;
  if (!difference && keySize)
  {
    FOR_VECTOR (i, keyOffsets)
    {
      CByteBuffer key;
      key.CopyFrom(_keyStore + keyOffsets[i], keySize);
      DecryptEcb(key, keySize, passwordKey, sizeof(passwordKey));
      const Byte *wrapKey = GetImageWrapKey(Read32(_keyStore + keyOffsets[i] - 28));
      MIRAY_CHECK(wrapKey)
      DecryptEcb(key, keySize, wrapKey, 32);
      if (i == 0)
        _key.CopyFrom(key, keySize);
      else if (memcmp(_key, key, keySize) != 0)
        keysAgree = false;
      key.Wipe();
    }
    if (!keysAgree)
      _key.Wipe();
  }
  memset(digest, 0, sizeof(digest));
  memset(passwordKey, 0, sizeof(passwordKey));
  // Win32 ERROR_INVALID_PASSWORD; preserves the error through the open callback.
  return difference ? (HRESULT)0x80070056 : keysAgree ? S_OK : S_FALSE;
}

HRESULT CHandler::ReadBlocks()
{
  FOR_VECTOR (i, _parts)
    RINOK(ReadPartBlocks(i))
  _blocks.Sort(CompareBlocks, NULL);
  unsigned blockIndex = 0;
  FOR_VECTOR (i, _parts)
  {
    const CPart &part = _parts[i];
    UInt64 next = 0;
    while (blockIndex < _blocks.Size() && _blocks[blockIndex].Part == i)
    {
      const CBlock &block = _blocks[blockIndex++];
      const UInt64 sector = block.Virt / _sectorSize - part.Base;
      MIRAY_CHECK(sector >= next
          && (_smart || _dependent || IsUnavailableRange(part, next, sector)))
      next = sector + block.Unpacked / _sectorSize;
    }
    MIRAY_CHECK(_smart || _dependent || IsUnavailableRange(part, next, part.Sectors))
  }
  MIRAY_CHECK(blockIndex == _blocks.Size())
  return S_OK;
}

HRESULT CHandler::ReadPartBlocks(unsigned partIndex)
{
  const CPart &part = _parts[partIndex];
  const CImageStream &s = _streams[part.StreamIndex];
  if (_rawImage)
  {
    MIRAY_CHECK(s.Size == part.Sectors * _sectorSize)
    for (UInt64 offset = 0; offset < s.Size;)
    {
      const UInt64 remain = s.Size - offset;
      CBlock b;
      b.Virt = part.Base * _sectorSize + offset;
      b.Pos = offset;
      b.Unpacked = remain < (1 << 22) ? (UInt32)remain : (1 << 22);
      b.Packed = b.Unpacked;
      b.Part = partIndex;
      b.Compressed = false;
      MIRAY_CHECK(_blocks.Size() < kItemLimit)
      _blocks.Add(b);
      offset += b.Unpacked;
    }
    return S_OK;
  }
  UInt64 pos = 0, next = 0, stored = 0;
  while (pos < s.Size)
  {
    Byte h[34];
    RINOK(ReadData(s, pos, h, 22))
    const bool compressed = memcmp(h, "CBLOCK1.0.00", 12) == 0;
    MIRAY_CHECK(compressed || memcmp(h, "BLOCKS0.0.01", 12) == 0)
    const UInt64 sector = Read64(h + 12);
    const bool end = sector == (UInt64)(Int64)-1;
    pos += 22;
    if (!end)
      RINOK(ReadData(s, pos, h + 22, 4))
    const unsigned headerSize = compressed && !end ? 26 : 22;
    UInt32 sum = 0;
    for (unsigned i = 0; i < headerSize; i += 2)
      sum += Read16(h + i);
    while (sum >> 16)
      sum = (sum & 0xffff) + (sum >> 16);
    MIRAY_CHECK(sum == 0xffff)
    if (end)
    {
      MIRAY_CHECK(pos == s.Size && stored == part.Stored
          && (_smart || _dependent || IsUnavailableRange(part, next, part.Sectors)))
      if (part.HasLast)
        MIRAY_CHECK(stored ? part.Last == next - 1 : part.Last == 0 || part.Last == (UInt64)(Int64)-1)
      return S_OK;
    }
    const UInt32 count = Read32(h + 22);
    MIRAY_CHECK(sector <= part.Sectors
        && count > 0 && count <= part.Sectors - sector
        && stored <= part.Stored && count <= part.Stored - stored
        && (UInt64)count * _sectorSize <= kBlockLimit && _blocks.Size() < kItemLimit)
    pos += 4;
    CBlock b;
    b.Virt = (part.Base + sector) * _sectorSize;
    b.Part = partIndex;
    b.Unpacked = count * _sectorSize;
    b.Compressed = compressed;
    if (compressed)
    {
      RINOK(ReadData(s, pos, h + 26, 8))
      MIRAY_CHECK(Read32(h + 26) == 0 && part.Method != 0)
      b.Packed = Read32(h + 30);
      pos += 8;
    }
    else
    {
      // A compressed region can store incompressible blocks verbatim.
      b.Packed = b.Unpacked;
    }
    MIRAY_CHECK(b.Packed > 0 && b.Packed <= kBlockLimit && pos <= s.Size && b.Packed <= s.Size - pos
        && (!_encryption || b.Packed % AES_BLOCK_SIZE == 0))
    b.Pos = pos;
    _blocks.Add(b);
    pos += b.Packed;
    if (sector + count > next)
      next = sector + count;
    stored += count;
  }
  return S_FALSE;
}

HRESULT CHandler::DecodeBlock(unsigned index)
{
  const CBlock &b = _blocks[index];
  const CPart &part = _parts[b.Part];
  _cacheIndex = (unsigned)-1;
  _cache.Alloc(b.Unpacked);
  if (!b.Compressed)
  {
    RINOK(ReadData(_streams[part.StreamIndex], b.Pos, _cache, b.Unpacked))
    MIRAY_CHECK(!_encryption || DecryptEcb(_cache, b.Unpacked, _key, (unsigned)_key.Size()))
  }
  else
  {
    _packed.Alloc(b.Packed);
    RINOK(ReadData(_streams[part.StreamIndex], b.Pos, _packed, b.Packed))
    MIRAY_CHECK(!_encryption || DecryptEcb(_packed, b.Packed, _key, (unsigned)_key.Size()))
    if (part.Method == 2)
    {
      MIRAY_CHECK(DecodeLz4(_packed, b.Packed, _cache, b.Unpacked, _encryption != 0))
    }
    else if (part.Method == 1)
    {
      _bufIn.Create_if_Empty();
      _bufOut.Create_if_Empty();
      _zlib.Create_if_Empty();
      _bufIn->Init(_packed, b.Packed);
      _bufOut->Init(_cache, b.Unpacked);
      const UInt64 size = b.Unpacked;
      RINOK(_zlib.Interface()->Code(_bufIn, _bufOut, NULL, &size, NULL))
      MIRAY_CHECK(_bufOut->GetPos() == b.Unpacked
          && CheckPadding(_packed, b.Packed, (size_t)_zlib->GetInputProcessedSize(), _encryption != 0))
    }
    else if (part.Method == 3)
    {
      SizeT out = b.Unpacked, in = b.Packed;
      ELzmaStatus status;
      const SRes result = LzmaDecode(_cache, &out, _packed, &in, part.LzmaProps,
          LZMA_PROPS_SIZE, LZMA_FINISH_END, &status, &g_Alloc);
      MIRAY_CHECK(result == SZ_OK && out == b.Unpacked && CheckPadding(_packed, b.Packed, in, _encryption != 0)
          && (status == LZMA_STATUS_FINISHED_WITH_MARK || status == LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK))
    }
    else
      return S_FALSE;
  }
  _cacheIndex = index;
  return S_OK;
}

HRESULT CHandler::ReadOverlayTable(unsigned streamIndex, const COverlayMap &map,
    unsigned level, UInt64 position, UInt64 virt,
    unsigned &items)
{
  const UInt64 bytes = (UInt64)map.Entries[level] * map.Width;
  MIRAY_CHECK(position <= map.End && bytes <= map.End - position
      && map.Entries[level] <= kItemLimit - items)
  items += map.Entries[level];
  CByteBuffer data;
  data.Alloc((size_t)bytes);
  RINOK(ReadData(_streams[streamIndex], position, data, data.Size()))
  for (UInt32 i = 0; i < map.Entries[level] && virt < _size; i++)
  {
    const UInt64 pointer = map.Width == 4 ? Read32(data + (size_t)i * 4) : Read64(data + (size_t)i * 8);
    const UInt64 unused = map.Width == 4 ? (UInt64)(UInt32)-1 : (UInt64)-1;
    if (pointer != unused)
    {
      MIRAY_CHECK(pointer > 0 && pointer < map.End / _sectorSize)
      const UInt64 offset = pointer * _sectorSize;
      if (level + 1 < map.Levels)
      {
        RINOK(ReadOverlayTable(streamIndex, map, level + 1, offset, virt, items))
      }
      else
      {
        MIRAY_CHECK(map.Span[level] <= map.End - offset)
        UInt64 remaining = _size - virt < map.Span[level] ? _size - virt : map.Span[level];
        UInt64 relative = 0;
        while (remaining)
        {
          MIRAY_CHECK(_blocks.Size() < kItemLimit)
          const UInt32 take = remaining < kBlockLimit ? (UInt32)remaining : kBlockLimit;
          CBlock &block = _blocks.AddNew_NoConstruct();
          block.Virt = virt + relative;
          block.Pos = offset + relative;
          block.Packed = block.Unpacked = take;
          block.Part = 0;
          block.Compressed = false;
          relative += take;
          remaining -= take;
        }
      }
    }
    if (map.Span[level] >= _size - virt)
      break;
    virt += map.Span[level];
  }
  return S_OK;
}

HRESULT CHandler::ReadOverlay()
{
  unsigned headerIndex = _streams.Size();
  FOR_VECTOR (i, _streams)
    if (_streams[i].Name == "_overlay")
      headerIndex = i;
  MIRAY_CHECK(headerIndex < _streams.Size() && _streams[headerIndex].Size == 132)
  Byte h[132];
  RINOK(ReadData(_streams[headerIndex], 0, h, sizeof(h)))
  MIRAY_CHECK(memcmp(h, "MSFF", 4) == 0 && Read32(h + 4) == 0x01000000
      && _baseId.Size() == 16
      && Read64(h + 96) == _sectorSize && Read64(h + 104) == _size / _sectorSize
      && Read64(h + 88) == _size && Read64(h + 72) >= _size)
  AString name;
  name.SetFrom((const char *)h + 8, 32);
  const int nul = name.Find((char)0);
  if (nul >= 0)
    name.DeleteFrom((unsigned)nul);
  unsigned streamIndex = 0;
  for (; streamIndex < _streams.Size(); streamIndex++)
    if (_streams[streamIndex].Name == name)
      break;
  MIRAY_CHECK(streamIndex < _streams.Size() && streamIndex != headerIndex)
  COverlayMap map;
  map.Width = h[131];
  map.Levels = 0;
  MIRAY_CHECK((map.Width == 4 || map.Width == 8) && h[130] < 32
      && ((UInt64)1 << h[130]) * map.Width == _sectorSize && Read32(h + 120) > 0)
  for (unsigned i = 0; i < 6; i++)
  {
    if (!h[124 + i])
    {
      for (unsigned j = i + 1; j < 6; j++)
        MIRAY_CHECK(h[124 + j] == 0)
      break;
    }
    map.Entries[map.Levels++] = (UInt32)h[124 + i] * (_sectorSize / map.Width);
  }
  MIRAY_CHECK(map.Levels > 0)
  map.Span[map.Levels - 1] = (UInt64)Read32(h + 120) * _sectorSize;
  for (unsigned i = map.Levels - 1; i > 0; i--)
  {
    MIRAY_CHECK(map.Span[i] <= (UInt64)-1 / map.Entries[i])
    map.Span[i - 1] = map.Span[i] * map.Entries[i];
  }
  MIRAY_CHECK(map.Span[0] <= (UInt64)-1 / map.Entries[0]
      && map.Span[0] * map.Entries[0] >= _size
      && Read64(h + 112) > 0 && Read64(h + 112) <= _streams[streamIndex].Size / _sectorSize)
  map.End = Read64(h + 112) * _sectorSize;
  unsigned items = 0;
  RINOK(ReadOverlayTable(streamIndex, map, 0, 0, 0, items))
  _parts[0].StreamIndex = streamIndex;
  return S_OK;
}

HRESULT CHandler::OpenStructure(IInStream *stream, IArchiveOpenCallback *openCallback)
{
  Stream = stream;
  _sectorSize = 512;
  _method = 0;
  _cacheIndex = (unsigned)-1;
  RINOK(InStream_GetSize_SeekToEnd(stream, _phySize))
  _totalPhysicalSize = _phySize;
  _firstPhysicalSize = _phySize;
  Byte sig[4];
  RINOK(ReadAt(0, sig, 4))
  _isMai = memcmp(sig, "HSAM", 4) == 0;
  if (_isMai)
    RINOK(OpenMai(openCallback))
  else
    RINOK(OpenMfi(openCallback))
  return ReadMetadata();
}

HRESULT CHandler::OpenContent(IArchiveOpenCallback *openCallback)
{
  RINOK(Unlock(openCallback))
  RINOK(VerifyMaiChecksums())
  RINOK(OpenBase(openCallback))
  return _overlay ? ReadOverlay() : ReadBlocks();
}

HRESULT CHandler::Open2(IInStream *stream, IArchiveOpenCallback *openCallback)
{
  RINOK(OpenStructure(stream, openCallback))
  return OpenContent(openCallback);
}

Z7_COM7F_IMF(CHandler::Read(void *data, UInt32 size, UInt32 *processedSize))
{
  if (processedSize)
    *processedSize = 0;
  if (_virtPos >= _size || size == 0)
    return S_OK;
  unsigned errorLow = 0, errorHigh = _unavailable.Size();
  while (errorLow < errorHigh)
  {
    const unsigned mid = errorLow + (errorHigh - errorLow) / 2;
    if (_unavailable[mid].Offset <= _virtPos)
      errorLow = mid + 1;
    else
      errorHigh = mid;
  }
  if (errorLow && _virtPos - _unavailable[errorLow - 1].Offset < _unavailable[errorLow - 1].Size)
  {
    _stream_unavailData = true;
    return S_OK;
  }
  if (errorLow < _unavailable.Size() && _unavailable[errorLow].Offset - _virtPos < size)
    size = (UInt32)(_unavailable[errorLow].Offset - _virtPos);
  unsigned low = 0, high = _blocks.Size();
  while (low < high)
  {
    const unsigned mid = low + (high - low) / 2;
    if (_blocks[mid].Virt <= _virtPos)
      low = mid + 1;
    else
      high = mid;
  }
  // Omitted SmartImage sectors read as zero. Gaps require no block entries
  // or buffers proportional to the logical disk size.
  if (low == 0 || _virtPos - _blocks[low - 1].Virt >= _blocks[low - 1].Unpacked)
  {
    MIRAY_CHECK(_smart || _base)
    const UInt64 end = low < _blocks.Size() ? _blocks[low].Virt : _size;
    MIRAY_CHECK(end > _virtPos)
    const UInt32 take = end - _virtPos < size ? (UInt32)(end - _virtPos) : size;
    if (_base)
    {
      RINOK(InStream_SeekSet(_base, _virtPos))
      RINOK(ReadStream_FALSE(_base, data, take))
    }
    else
      memset(data, 0, take);
    _virtPos += take;
    if (processedSize)
      *processedSize = take;
    return S_OK;
  }
  const unsigned index = low - 1;
  const CBlock &b = _blocks[index];
  const UInt64 offset = _virtPos - b.Virt;
  MIRAY_CHECK(offset < b.Unpacked)
  if (_cacheIndex != index)
  {
    const HRESULT result = DecodeBlock(index);
    if (result != S_OK)
    {
      _stream_dataError = true;
      return result;
    }
  }
  const UInt32 take = size < b.Unpacked - offset ? size : (UInt32)(b.Unpacked - offset);
  memcpy(data, _cache + (size_t)offset, take);
  _virtPos += take;
  if (processedSize)
    *processedSize = take;
  return S_OK;
}

Z7_COM7F_IMF(CHandler::GetStream(UInt32 /* index */, ISequentialInStream **stream))
{
  *stream = NULL;
  if (!Stream)
    return S_FALSE;
  Reset_VirtPos();
  CMyComPtr<ISequentialInStream> result = this;
  *stream = result.Detach();
  return S_OK;
}

Z7_COM7F_IMF(CHandler::Close())
{
  _streams.Clear();
  _parts.Clear();
  _maiVolumes.Clear();
  _maiVolumeRecords.Clear();
  _maiChecksums.Clear();
  _base.Release();
  _imageId.Free();
  _baseId.Free();
  _parentName.Empty();
  _sourceName.Empty();
  _depth = 0;
  _dependent = false;
  _overlay = false;
  _growableMfi = false;
  _blocks.Clear();
  _unavailable.Clear();
  _cache.Free();
  _packed.Free();
  _key.Wipe();
  _key.Free();
  _keyStore.Free();
  _salt.Free();
  _verifier.Free();
  Stream.Release();
  _phySize = 0;
  _totalPhysicalSize = 0;
  _firstPhysicalSize = 0;
  _numVolumes = 1;
  _maiChunkSize = 0;
  _maiMaxChunks = 0;
  _splitSize = (UInt64)(Int64)-1;
  _version = 0;
  _method = 0;
  _smart = false;
  _rawImage = false;
  _encryption = 0;
  _protected = false;
  _sectorSize = 512;
  Clear_HandlerImg_Vars();
  return S_OK;
}

static const Byte kProps[] = { kpidSize, kpidPackSize, kpidEncrypted };
static const Byte kArcProps[] = { kpidSectorSize, kpidMethod, kpidUnpackVer, kpidComment,
  kpidEncrypted, kpidNumVolumes, kpidTotalPhySize };
IMP_IInArchive_Props
IMP_IInArchive_ArcProps

Z7_COM7F_IMF(CHandler::GetProperty(UInt32 /* index */, PROPID propID, PROPVARIANT *value))
{
  COM_TRY_BEGIN
  NCOM::CPropVariant prop;
  switch (propID)
  {
    case kpidSize: prop = _size; break;
    case kpidPackSize: prop = _totalPhysicalSize; break;
    case kpidEncrypted: prop = _protected; break;
    case kpidExtension: prop = _imgExt ? _imgExt : "img"; break;
  }
  prop.Detach(value);
  return S_OK;
  COM_TRY_END
}

Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
{
  COM_TRY_BEGIN
  NCOM::CPropVariant prop;
  switch (propID)
  {
    case kpidMainSubfile: prop = (UInt32)0; break;
    case kpidPhySize: prop = _firstPhysicalSize; break;
    case kpidTotalPhySize: prop = _totalPhysicalSize; break;
    case kpidNumVolumes: prop = _numVolumes; break;
    case kpidSectorSize: prop = _sectorSize; break;
    case kpidUnpackVer: prop = _version; break;
    case kpidEncrypted: prop = _protected; break;
    case kpidComment:
      prop = _overlay ? "Miray Overlay Image"
          : _smart ? "Miray SmartImage (omitted sectors read as zero)"
          : _isMai ? "Miray Archive Image" : "Miray File Image";
      break;
    case kpidMethod:
    {
      static const char * const names[] = { "Copy", "Deflate", "LZ4", "LZMA", "Mixed" };
      if (_method < Z7_ARRAY_SIZE(names))
        prop = names[_method];
      break;
    }
  }
  prop.Detach(value);
  return S_OK;
  COM_TRY_END
}

// Temporary local format ID; an upstream ID must be assigned by the maintainer.
REGISTER_ARC_I("Miray", "mfi mai mfd mfo", NULL, 0xBE,
  kSignatures, 0, NArcInfoFlags::kMultiSignature, NULL)

#undef MIRAY_CHECK

}}
