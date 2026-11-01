// sniffindex: turns an 802.11 sniffer capture into a TSV, in the columns of tshark -T fields.
//
// It only reads the MAC header at its fixed place, which is why it takes a second where
// dissecting the capture takes a minute. See README.md.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

namespace {

namespace fs = std::filesystem;

constexpr auto Version = "1.0.0";
constexpr auto Header = "frame.number\tframe.time_relative\twlan.fc.type_subtype\twlan.addr\t"
                        "wlan.ta\twlan.seq\twlan.fc.retry\twlan.fc.protected\tip.id\n";

constexpr uint32_t LinkRaw80211 = 105;
constexpr uint32_t LinkPrism = 119;
constexpr uint32_t LinkRadiotap = 127;
constexpr uint32_t LinkAvs = 163;
constexpr uint32_t LinkPpi = 192;

// Anything bigger is a damaged file, not a frame
constexpr uint32_t MaxBlockSize = 64 * 1024 * 1024;
constexpr size_t ReadBufferSize = 4 * 1024 * 1024;
constexpr size_t WriteBufferSize = 4 * 1024 * 1024;
constexpr size_t LongestRow = 512;

constexpr uint8_t FlagMoreFragments = 0x04;
constexpr uint8_t FlagRetry = 0x08;
constexpr uint8_t FlagProtected = 0x40;
constexpr uint8_t FlagOrder = 0x80;

enum FrameType { Management = 0, Control = 1, Data = 2 };

const uint8_t LlcIpv4[] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00 };

struct Failure : std::runtime_error {
    using std::runtime_error::runtime_error;
};

uint16_t le16( const uint8_t* p )
{
    return static_cast<uint16_t>( p[ 0 ] | p[ 1 ] << 8 );
}

uint16_t be16( const uint8_t* p )
{
    return static_cast<uint16_t>( p[ 0 ] << 8 | p[ 1 ] );
}

uint32_t le32( const uint8_t* p )
{
    return uint32_t{ p[ 0 ] } | uint32_t{ p[ 1 ] } << 8 | uint32_t{ p[ 2 ] } << 16
           | uint32_t{ p[ 3 ] } << 24;
}

uint32_t be32( const uint8_t* p )
{
    return uint32_t{ p[ 0 ] } << 24 | uint32_t{ p[ 1 ] } << 16 | uint32_t{ p[ 2 ] } << 8
           | uint32_t{ p[ 3 ] };
}

FILE* openFile( const fs::path& path, bool write )
{
#ifdef _WIN32
    // The wide API: the ANSI one can't name every file, a path in Chinese on another locale
    return _wfopen( path.c_str(), write ? L"wb" : L"rb" );
#else
    return std::fopen( path.c_str(), write ? "wb" : "rb" );
#endif
}

class Input {
  public:
    explicit Input( const fs::path& path )
        : file_( openFile( path, false ) )
        , buffer_( ReadBufferSize )
    {
        if ( file_ == nullptr ) {
            throw Failure( "can't open the capture" );
        }
    }

    ~Input()
    {
        if ( file_ != nullptr ) {
            std::fclose( file_ );
        }
    }

    Input( const Input& ) = delete;
    Input& operator=( const Input& ) = delete;

    // The next bytes, valid until the following call. Null if the file ends before them.
    const uint8_t* read( size_t size )
    {
        if ( end_ - position_ < size ) {
            refill( size );
            if ( end_ - position_ < size ) {
                return nullptr;
            }
        }
        const auto* data = buffer_.data() + position_;
        position_ += size;
        return data;
    }

    bool atEnd()
    {
        if ( position_ == end_ ) {
            refill( 1 );
        }
        return position_ == end_;
    }

  private:
    void refill( size_t size )
    {
        if ( size > buffer_.size() ) {
            buffer_.resize( size );
        }
        std::memmove( buffer_.data(), buffer_.data() + position_, end_ - position_ );
        end_ -= position_;
        position_ = 0;
        end_ += std::fread( buffer_.data() + end_, 1, buffer_.size() - end_, file_ );
    }

    FILE* file_;
    std::vector<uint8_t> buffer_;
    size_t position_ = 0;
    size_t end_ = 0;
};

class Output {
  public:
    explicit Output( FILE* file )
        : file_( file )
        , buffer_( WriteBufferSize )
    {
    }

    char* reserve()
    {
        if ( buffer_.size() - size_ < LongestRow ) {
            flush();
        }
        return buffer_.data() + size_;
    }

    void commit( const char* end )
    {
        size_ = static_cast<size_t>( end - buffer_.data() );
    }

    void flush()
    {
        if ( std::fwrite( buffer_.data(), 1, size_, file_ ) != size_ ) {
            throw Failure( "can't write the result" );
        }
        size_ = 0;
    }

  private:
    FILE* file_;
    std::vector<char> buffer_;
    size_t size_ = 0;
};

const char* const HexDigits = "0123456789abcdef";

char* writeAddress( char* out, const uint8_t* address )
{
    for ( auto i = 0; i < 6; ++i ) {
        if ( i != 0 ) {
            *out++ = ':';
        }
        *out++ = HexDigits[ address[ i ] >> 4 ];
        *out++ = HexDigits[ address[ i ] & 0x0f ];
    }
    return out;
}

char* writeHex16( char* out, unsigned value )
{
    *out++ = '0';
    *out++ = 'x';
    for ( auto shift = 12; shift >= 0; shift -= 4 ) {
        *out++ = HexDigits[ ( value >> shift ) & 0x0f ];
    }
    return out;
}

char* writeNumber( char* out, uint64_t value, int minimumDigits = 1 )
{
    char digits[ 24 ];
    auto count = 0;
    while ( value != 0 || count < minimumDigits ) {
        digits[ count++ ] = static_cast<char>( '0' + value % 10 );
        value /= 10;
    }
    while ( count > 0 ) {
        *out++ = digits[ --count ];
    }
    return out;
}

char* writeText( char* out, const char* text )
{
    while ( *text != '\0' ) {
        *out++ = *text++;
    }
    return out;
}

char* writeBool( char* out, bool value )
{
    return writeText( out, value ? "True" : "False" );
}

char* writeTime( char* out, int64_t nanoseconds )
{
    if ( nanoseconds < 0 ) {
        *out++ = '-';
        nanoseconds = -nanoseconds;
    }
    out = writeNumber( out, static_cast<uint64_t>( nanoseconds ) / 1000000000 );
    *out++ = '.';
    return writeNumber( out, static_cast<uint64_t>( nanoseconds ) % 1000000000, 9 );
}

struct ControlLayout {
    int addresses;
    bool hasTransmitter;
};

// Which of the two possible addresses a control frame has, by subtype
ControlLayout controlLayout( int subtype )
{
    switch ( subtype ) {
    case 0x0: // reserved
    case 0x1:
    case 0x7: // control wrapper
    case 0xc: // CTS
    case 0xd: // ACK
        return { 1, false };
    case 0xe: // CF-End: the second address is the BSSID
        return { 2, false };
    default:
        return { 2, true };
    }
}

ControlLayout extensionLayout( int extension )
{
    return extension == 6 ? ControlLayout{ 1, false } : ControlLayout{ 2, true };
}

bool isIpv4( const uint8_t* payload, size_t size )
{
    constexpr size_t IdEnd = sizeof( LlcIpv4 ) + 6;
    if ( size < IdEnd || std::memcmp( payload, LlcIpv4, sizeof( LlcIpv4 ) ) != 0 ) {
        return false;
    }
    const auto version = payload[ sizeof( LlcIpv4 ) ];
    return version >> 4 == 4 && ( version & 0x0f ) >= 5;
}

char* writeIpId( char* out, const uint8_t* payload )
{
    return writeHex16( out, be16( payload + sizeof( LlcIpv4 ) + 4 ) );
}

char* writeIpIds( char* out, const uint8_t* frame, size_t size, size_t headerSize, bool aggregate )
{
    if ( !aggregate ) {
        if ( isIpv4( frame + headerSize, size - headerSize ) ) {
            out = writeIpId( out, frame + headerSize );
        }
        return out;
    }

    constexpr size_t SubframeHeaderSize = 14;
    constexpr int MaxListedIds = 16;
    auto listed = 0;
    auto offset = headerSize;
    while ( offset + SubframeHeaderSize <= size && listed < MaxListedIds ) {
        const auto* subframe = frame + offset;
        const auto length = be16( subframe + 12 );
        const auto* payload = subframe + SubframeHeaderSize;
        const auto available = size - offset - SubframeHeaderSize;
        if ( isIpv4( payload, available < length ? available : length ) ) {
            if ( listed++ != 0 ) {
                *out++ = ',';
            }
            out = writeIpId( out, payload );
        }
        offset += SubframeHeaderSize + length;
        offset += ( 4 - ( offset - headerSize ) % 4 ) % 4;
    }
    return out;
}

char* writeControlColumns( char* out, const uint8_t* frame, size_t size, int subtype )
{
    const auto extended = subtype == 6;
    const auto extension = frame[ 1 ] & 0x0f;
    const auto layout = extended ? extensionLayout( extension ) : controlLayout( subtype );

    const auto headerSize = static_cast<size_t>( 4 + layout.addresses * 6 );
    if ( size < headerSize ) {
        return writeText( out, "\t\t\t\t\t\t" );
    }

    out = writeHex16( out, static_cast<unsigned>( extended ? 0x160 | extension : 0x10 | subtype ) );
    *out++ = '\t';
    out = writeAddress( out, frame + 4 );
    if ( layout.addresses == 2 ) {
        *out++ = ',';
        out = writeAddress( out, frame + 10 );
    }
    *out++ = '\t';
    if ( layout.hasTransmitter ) {
        out = writeAddress( out, frame + 10 );
    }
    out = writeText( out, "\t\t" );
    if ( !extended ) {
        out = writeBool( out, frame[ 1 ] & FlagRetry );
        *out++ = '\t';
        out = writeBool( out, frame[ 1 ] & FlagProtected );
    }
    else {
        *out++ = '\t';
    }
    return writeText( out, "\t" );
}

char* writeHeaderColumns( char* out, const uint8_t* frame, size_t size, int type, int subtype )
{
    const auto flags = frame[ 1 ];
    const auto fourAddresses = type == Data && ( flags & 0x03 ) == 0x03;
    const auto qos = type == Data && ( subtype & 0x8 ) != 0;
    const auto headerBeforeQos = fourAddresses ? 30u : 24u;
    const auto headerSize = headerBeforeQos + ( qos ? 2u : 0u )
                            + ( qos && ( flags & FlagOrder ) != 0 ? 4u : 0u );
    if ( size < headerSize ) {
        return writeText( out, "\t\t\t\t\t\t" );
    }

    out = writeHex16( out, static_cast<unsigned>( type << 4 | subtype ) );
    *out++ = '\t';
    out = writeAddress( out, frame + 4 );
    *out++ = ',';
    out = writeAddress( out, frame + 10 );
    // In an A-MSDU the source or destination of the header is the one of each subframe
    const auto aggregate = qos && ( frame[ headerBeforeQos ] & 0x80 ) != 0;
    const auto oneWay = ( flags & 0x03 ) == 0x01 || ( flags & 0x03 ) == 0x02;
    if ( !aggregate || !oneWay ) {
        *out++ = ',';
        out = writeAddress( out, frame + 16 );
    }
    if ( fourAddresses && !aggregate ) {
        *out++ = ',';
        out = writeAddress( out, frame + 24 );
    }
    *out++ = '\t';
    out = writeAddress( out, frame + 10 );
    *out++ = '\t';
    out = writeNumber( out, le16( frame + 22 ) >> 4u );
    *out++ = '\t';
    out = writeBool( out, flags & FlagRetry );
    *out++ = '\t';
    out = writeBool( out, flags & FlagProtected );
    *out++ = '\t';

    const auto hasPayload = type == Data && ( subtype & 0x4 ) == 0;
    if ( hasPayload && ( flags & ( FlagProtected | FlagMoreFragments ) ) == 0 ) {
        out = writeIpIds( out, frame, size, headerSize, aggregate );
    }
    return out;
}

char* writeFrameColumns( char* out, const uint8_t* frame, size_t size )
{
    if ( size < 2 ) {
        return writeText( out, "\t\t\t\t\t\t" );
    }

    const auto type = ( frame[ 0 ] >> 2 ) & 0x03;
    const auto subtype = frame[ 0 ] >> 4;
    switch ( type ) {
    case Management:
    case Data:
        return writeHeaderColumns( out, frame, size, type, subtype );
    case Control:
        return writeControlColumns( out, frame, size, subtype );
    default:
        // Extension frames have no header sniffindex knows about
        return writeText( out, "\t\t\t\t\t\t" );
    }
}

// Where the 802.11 frame starts, past the header of the sniffer. Nothing is left if the
// header claims more than the record holds.
size_t linkHeaderSize( uint32_t linkType, const uint8_t* data, size_t size )
{
    constexpr size_t PrismHeaderSize = 144;
    size_t skipped = 0;
    switch ( linkType ) {
    case LinkRaw80211:
        break;
    case LinkRadiotap:
    case LinkPpi:
        skipped = size < 4 ? size : le16( data + 2 );
        break;
    case LinkPrism:
        if ( size >= 8 && ( be32( data ) & 0xfffffff0 ) == 0x80211000 ) {
            skipped = be32( data + 4 );
        }
        else {
            skipped = PrismHeaderSize;
        }
        break;
    case LinkAvs:
        skipped = size < 8 ? size : be32( data + 4 );
        break;
    default:
        throw Failure( "link type " + std::to_string( linkType )
                       + " is not 802.11, or not one sniffindex reads: use tshark" );
    }
    return skipped < size ? skipped : size;
}

// Radiotap can say that the frame ends with its 4 bytes of FCS, which are not payload
size_t radiotapFcsSize( const uint8_t* header, size_t headerSize )
{
    constexpr uint32_t PresentTsft = 1u << 0;
    constexpr uint32_t PresentFlags = 1u << 1;
    constexpr uint32_t PresentExtended = 1u << 31;
    constexpr uint8_t FlagsHaveFcs = 0x10;

    if ( headerSize < 8 ) {
        return 0;
    }
    const auto present = le32( header + 4 );
    size_t offset = 8;
    for ( auto word = present; ( word & PresentExtended ) != 0; offset += 4 ) {
        if ( offset + 4 > headerSize ) {
            return 0;
        }
        word = le32( header + offset );
    }
    if ( ( present & PresentTsft ) != 0 ) {
        offset = ( ( offset + 7 ) & ~size_t{ 7 } ) + 8;
    }
    if ( ( present & PresentFlags ) == 0 || offset >= headerSize ) {
        return 0;
    }
    return ( header[ offset ] & FlagsHaveFcs ) != 0 ? 4 : 0;
}

void checkLinkType( uint32_t linkType, const uint8_t* record, size_t size )
{
    constexpr uint32_t PpiInnerOffset = 4;
    if ( linkType == LinkPpi && size >= PpiInnerOffset + 4
         && le32( record + PpiInnerOffset ) != LinkRaw80211 ) {
        throw Failure( "PPI holding link type "
                       + std::to_string( le32( record + PpiInnerOffset ) )
                       + " is not supported: use tshark" );
    }
}

class Indexer {
  public:
    explicit Indexer( Output& output )
        : output_( output )
    {
        std::memcpy( output_.reserve(), Header, std::strlen( Header ) );
        output_.commit( output_.reserve() + std::strlen( Header ) );
    }

    void frame( uint32_t linkType, const uint8_t* record, size_t size, int64_t nanoseconds )
    {
        checkLinkType( linkType, record, size );
        if ( frames_ == 0 ) {
            firstTime_ = nanoseconds;
        }
        ++frames_;

        const auto skipped = linkHeaderSize( linkType, record, size );
        auto frameSize = size - skipped;
        if ( linkType == LinkRadiotap ) {
            const auto fcsSize = radiotapFcsSize( record, skipped );
            frameSize -= fcsSize < frameSize ? fcsSize : frameSize;
        }

        auto* out = output_.reserve();
        out = writeNumber( out, frames_ );
        *out++ = '\t';
        out = writeTime( out, nanoseconds - firstTime_ );
        *out++ = '\t';
        out = writeFrameColumns( out, record + skipped, frameSize );
        *out++ = '\n';
        output_.commit( out );
    }

    uint64_t frames() const
    {
        return frames_;
    }

  private:
    Output& output_;
    uint64_t frames_ = 0;
    int64_t firstTime_ = 0;
};

void readPcap( Input& input, Indexer& indexer, const uint8_t* start, bool& truncated )
{
    const auto magic = le32( start );
    const auto swapped = magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1;
    const auto u32 = swapped ? be32 : le32;
    const auto nanosecondFile = magic == 0xa1b23c4d || magic == 0x4d3cb2a1;

    const auto* rest = input.read( 20 );
    if ( rest == nullptr ) {
        throw Failure( "the capture ends inside its header" );
    }
    const auto linkType = u32( rest + 16 ) & 0x0fffffff;
    checkLinkType( linkType, nullptr, 0 );
    linkHeaderSize( linkType, nullptr, 0 );

    while ( !input.atEnd() ) {
        const auto* header = input.read( 16 );
        if ( header == nullptr ) {
            truncated = true;
            return;
        }
        const int64_t seconds = u32( header );
        const int64_t fraction = u32( header + 4 );
        const auto size = u32( header + 8 );
        if ( size > MaxBlockSize ) {
            throw Failure( "damaged capture: a frame of " + std::to_string( size ) + " bytes" );
        }
        const auto* record = input.read( size );
        if ( record == nullptr ) {
            truncated = true;
            return;
        }
        indexer.frame( linkType, record, size,
                       seconds * 1000000000 + ( nanosecondFile ? fraction : fraction * 1000 ) );
    }
}

struct Interface {
    uint32_t linkType;
    uint32_t captureLimit;
    // Timestamps in units of 10^-decimals seconds, or of 2^-binaryShift ones if that is set
    int decimals = 6;
    int binaryShift = 0;
    int64_t offsetSeconds = 0;

    int64_t nanoseconds( uint64_t ticks ) const
    {
        constexpr uint64_t Billion = 1000000000;
        int64_t result = 0;
        if ( binaryShift != 0 ) {
            const auto whole = ticks >> binaryShift;
            const auto part = ticks & ( ( uint64_t{ 1 } << binaryShift ) - 1 );
            result = static_cast<int64_t>( whole * Billion + ( part * Billion >> binaryShift ) );
        }
        else {
            auto value = ticks;
            for ( auto i = decimals; i < 9; ++i ) {
                value *= 10;
            }
            for ( auto i = 9; i < decimals; ++i ) {
                value /= 10;
            }
            result = static_cast<int64_t>( value );
        }
        return result + offsetSeconds * static_cast<int64_t>( Billion );
    }
};

class PcapngReader {
  public:
    PcapngReader( Input& input, Indexer& indexer )
        : input_( input )
        , indexer_( indexer )
    {
    }

    void read( bool& truncated )
    {
        while ( !input_.atEnd() ) {
            const auto* head = input_.read( 12 );
            if ( head == nullptr ) {
                truncated = true;
                return;
            }
            uint8_t start[ 12 ];
            std::memcpy( start, head, sizeof( start ) );

            const auto type = le32( start );
            if ( type == 0x0a0d0d0a ) {
                swapped_ = le32( start + 8 ) == 0x4d3c2b1a;
                interfaces_.clear();
            }
            const auto u32 = swapped_ ? be32 : le32;
            const auto size = u32( start + 4 );
            if ( size < 12 || size % 4 != 0 || size > MaxBlockSize ) {
                throw Failure( "damaged capture: a block of " + std::to_string( size )
                               + " bytes" );
            }
            const auto* body = input_.read( size - 12 );
            if ( body == nullptr ) {
                truncated = true;
                return;
            }
            handleBlock( swapped_ ? be32( start ) : type, start + 8, body, size - 12 );
        }
    }

  private:
    // The first 4 bytes of the body are in "first", the block trailer is the last 4 of body
    void handleBlock( uint32_t type, const uint8_t* first, const uint8_t* rest, size_t restSize )
    {
        blockBody_.resize( restSize + 4 );
        std::memcpy( blockBody_.data(), first, 4 );
        std::memcpy( blockBody_.data() + 4, rest, restSize );
        const auto* body = blockBody_.data();
        const auto bodySize = restSize; // without the trailer, with the 4 first bytes

        if ( type == 1 ) {
            addInterface( body, bodySize );
        }
        else if ( type == 6 && bodySize >= 20 ) {
            enhancedPacket( body, bodySize );
        }
        else if ( type == 3 && bodySize >= 4 ) {
            simplePacket( body, bodySize );
        }
    }

    uint16_t u16( const uint8_t* p ) const
    {
        return swapped_ ? be16( p ) : le16( p );
    }

    uint32_t u32( const uint8_t* p ) const
    {
        return swapped_ ? be32( p ) : le32( p );
    }

    void addInterface( const uint8_t* body, size_t size )
    {
        if ( size < 8 ) {
            throw Failure( "damaged capture: a short interface block" );
        }
        Interface added{ u16( body ), u32( body + 4 ) };
        size_t offset = 8;
        while ( offset + 4 <= size ) {
            const auto code = u16( body + offset );
            const size_t length = u16( body + offset + 2 );
            const auto* value = body + offset + 4;
            if ( code == 0 || offset + 4 + length > size ) {
                break;
            }
            if ( code == 9 && length == 1 ) {
                if ( *value & 0x80 ) {
                    added.binaryShift = *value & 0x7f;
                }
                else {
                    added.decimals = *value;
                }
            }
            else if ( code == 14 && length == 8 ) {
                const uint64_t high = u32( value + ( swapped_ ? 0 : 4 ) );
                const uint64_t low = u32( value + ( swapped_ ? 4 : 0 ) );
                added.offsetSeconds = static_cast<int64_t>( high << 32 | low );
            }
            offset += 4 + ( length + 3 ) / 4 * 4;
        }
        linkHeaderSize( added.linkType, nullptr, 0 );
        interfaces_.push_back( added );
    }

    const Interface& interfaceAt( uint32_t index ) const
    {
        if ( index >= interfaces_.size() ) {
            throw Failure( "damaged capture: a packet of an unknown interface" );
        }
        return interfaces_[ index ];
    }

    void enhancedPacket( const uint8_t* body, size_t size )
    {
        const auto& source = interfaceAt( u32( body ) );
        const uint64_t ticks = static_cast<uint64_t>( u32( body + 4 ) ) << 32 | u32( body + 8 );
        size_t captured = u32( body + 12 );
        if ( captured > size - 20 ) {
            captured = size - 20;
        }
        lastTime_ = source.nanoseconds( ticks );
        indexer_.frame( source.linkType, body + 20, captured, lastTime_ );
    }

    // Has no timestamp, it stays at the one of the packet before
    void simplePacket( const uint8_t* body, size_t size )
    {
        const auto& source = interfaceAt( 0 );
        size_t captured = u32( body );
        if ( source.captureLimit != 0 && captured > source.captureLimit ) {
            captured = source.captureLimit;
        }
        if ( captured > size - 4 ) {
            captured = size - 4;
        }
        indexer_.frame( source.linkType, body + 4, captured, lastTime_ );
    }

    Input& input_;
    Indexer& indexer_;
    std::vector<Interface> interfaces_;
    std::vector<uint8_t> blockBody_;
    bool swapped_ = false;
    int64_t lastTime_ = 0;
};

uint64_t index( const fs::path& capture, FILE* result )
{
    Input input( capture );
    const auto* start = input.read( 4 );
    if ( start == nullptr ) {
        throw Failure( "not a capture" );
    }
    uint8_t magicBytes[ 4 ];
    std::memcpy( magicBytes, start, sizeof( magicBytes ) );

    const auto magic = le32( magicBytes );
    const auto isPcap = magic == 0xa1b2c3d4 || magic == 0xa1b23c4d || magic == 0xd4c3b2a1
                        || magic == 0x4d3cb2a1;
    if ( ( magic & 0xffff ) == 0x8b1f || magic == 0xfd2fb528 || magic == 0x184d2204 ) {
        throw Failure( "the capture is compressed: unpack it first, or use tshark" );
    }

    Output output( result );
    Indexer indexer( output );
    auto truncated = false;
    if ( isPcap ) {
        readPcap( input, indexer, magicBytes, truncated );
    }
    else if ( magic == 0x0a0d0d0a ) {
        // Back to the beginning: the reader wants the whole first block
        Input again( capture );
        PcapngReader( again, indexer ).read( truncated );
    }
    else {
        throw Failure( "not a capture" );
    }
    output.flush();

    if ( truncated ) {
        std::fprintf( stderr, "warning: the capture ends in the middle of a frame\n" );
    }
    return indexer.frames();
}

int usage( FILE* stream )
{
    std::fprintf( stream, "usage: sniffindex <capture> [-o <result.tsv>]\n"
                          "Writes the 802.11 headers of a pcap or pcapng file as a TSV, to the\n"
                          "standard output without -o. Columns are those of tshark -T fields.\n" );
    return stream == stderr ? 2 : 0;
}

int run( const std::vector<fs::path>& arguments )
{
    fs::path capture;
    fs::path resultPath;
    auto toFile = false;
    for ( size_t i = 0; i < arguments.size(); ++i ) {
        const auto& argument = arguments[ i ];
        if ( argument == "--help" || argument == "-h" ) {
            return usage( stdout );
        }
        if ( argument == "--version" ) {
            std::printf( "sniffindex %s\n", Version );
            return 0;
        }
        if ( argument == "-o" ) {
            if ( ++i == arguments.size() ) {
                return usage( stderr );
            }
            resultPath = arguments[ i ];
            toFile = true;
        }
        else if ( capture.empty() ) {
            capture = argument;
        }
        else {
            return usage( stderr );
        }
    }
    if ( capture.empty() ) {
        return usage( stderr );
    }

    FILE* result = stdout;
    if ( toFile ) {
        result = openFile( resultPath, true );
        if ( result == nullptr ) {
            std::fprintf( stderr, "sniffindex: can't create the result\n" );
            return 1;
        }
    }
#ifdef _WIN32
    else {
        // Text mode would write CRLF, and break comparing with tshark
        _setmode( _fileno( stdout ), _O_BINARY );
    }
#endif

    auto code = 0;
    try {
        const auto frames = index( capture, result );
        std::fprintf( stderr, "%llu frames\n", static_cast<unsigned long long>( frames ) );
    }
    catch ( const Failure& failure ) {
        std::fprintf( stderr, "sniffindex: %s\n", failure.what() );
        code = 1;
    }

    if ( toFile ) {
        std::fclose( result );
        if ( code != 0 ) {
            std::error_code ignored;
            fs::remove( resultPath, ignored );
        }
    }
    return code;
}

} // namespace

#ifdef _WIN32
int wmain( int argc, wchar_t* argv[] )
#else
int main( int argc, char* argv[] )
#endif
{
    return run( std::vector<fs::path>( argv + 1, argv + argc ) );
}
