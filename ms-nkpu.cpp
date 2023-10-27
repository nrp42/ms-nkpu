#include <config.h>

#include "ms-nkpu.h"
#include "ms-nkpu-log.h"

#include <util/strutil.h>
#include <util/encode/hex.h>
#include <cc/simple_parser.h>
#include <dhcp/dhcp4.h>
#include <dhcp/dhcp6.h>
#include <dhcp/libdhcp++.h>
#include <dhcp/option_definition.h>
#include <dhcp/option_space.h>
#include <dhcp/option_vendor.h>
#include <dhcp/option_vendor_class.h>
#include <dhcpsrv/cfgmgr.h>
#include <eval/eval_context.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <fstream>

using namespace isc;
using namespace isc::data;
using namespace isc::dhcp;
using namespace isc::eval;
using namespace nrp::ms_nkpu;
using namespace isc::log;
using namespace isc::util;
using namespace std;

namespace nrp {
namespace ms_nkpu {

const string MsNkpu::ParamKeys = "unlock-keys";
const string MsNkpu::ParamCertFile = "certfile";
const string MsNkpu::ParamKeyFile = "keyfile";

MsNkpu::~MsNkpu()
{
	Reset();
};

void MsNkpu::Reset()
{
	_unlockKeys.clear();
}

void MsNkpu::Configure( ConstElementPtr options )
{
	if( !options )
		isc_throw( ConfigError, "'" << ParamKeys << "' parameter is mandatory" );
	if( options->getType() != Element::list )
		isc_throw( ConfigError, "'" << ParamKeys << "' parameter must be a list" );
	if( options->empty() )
		return;

	for( auto option : options->listValue() )
	{
		if( !option )
			isc_throw( ConfigError, "null option element" );
		if( option->getType() != Element::map )
			isc_throw( ConfigError, "option element is not a map" );

		string pkey;
		string cert;

		for( auto entry : option->mapValue() )
			if( entry.first == ParamCertFile )
			{
				if( entry.second->getType() != Element::string )
					isc_throw( ConfigError, "'" << entry.first << "' must be a string" );
				cert = entry.second->stringValue();
			}
			else if( entry.first == ParamKeyFile )
			{
				if( entry.second->getType() != Element::string )
					isc_throw( ConfigError, "'" << entry.first << "' must be a string" );
				pkey = entry.second->stringValue();
			}
			else
				isc_throw( ConfigError, "unknown parameter '" << entry.first << "'" );

		if( pkey.empty() )
			isc_throw( ConfigError, "'" << ParamKeyFile << " missing" );
		if( cert.empty() )
			isc_throw( ConfigError, "'" << ParamCertFile << " missing" );

		_unlockKeys.insert( { GetX509Digest( cert ), LoadPrivateKey( pkey ) } );
	}
}

void MsNkpu::PreProcess( Pkt4& query )
{
	if( query.getType() != DHCP_NOTYPE )
		return;

	if( query.getOp() != BOOTREQUEST )
		return;

	auto vc = query.getOption( DHO_VENDOR_CLASS_IDENTIFIER );
	if( vc == nullptr )
		return;

	if( vc->toString() != "BITLOCKER" )
		return;

	query.setType( DHCPREQUEST );
	query.addClass( "BITLOCKER" );
	LOG_INFO( nkpu_logger, MSNKPU_REQUEST ).arg( query.getLabel() );
}

bool MsNkpu::Process( Pkt4& query, Pkt4& response )
{
	if( !query.inClass( "BITLOCKER" ) )
		return true;

	if( query.getType() != DHCPREQUEST )
		return false;

	auto vc = query.getOption( DHO_VENDOR_CLASS_IDENTIFIER );
	if( vc == nullptr )
		return false;

	if( vc->toString() != "BITLOCKER" )
		return false;

	auto opt43 = query.getOption( DHO_VENDOR_ENCAPSULATED_OPTIONS );
	if( opt43 == nullptr )
		isc_throw( Unexpected, "malformed NKPU unlock request packet" );

	auto opt431 = opt43->getOption( 1 );
	if( opt431 == nullptr )
		isc_throw( Unexpected, "malformed NKPU unlock request packet" );

	if( opt431->getData().size() != 20 )
		isc_throw( Unexpected, "malformed NKPU unlock request packet" );

	auto opt432 = opt43->getOption( 2 );
	if( opt432 == nullptr )
		isc_throw( Unexpected, "malformed NKPU unlock request packet" );

	auto opt125 = query.getOption( DHO_VIVSO_SUBOPTIONS );
	if( opt125 == nullptr )
		isc_throw( Unexpected, "malformed NKPU unlock request packet" );

	auto opt1251 = opt125->getOption( 1 );
	if( opt1251 == nullptr )
		isc_throw( Unexpected, "malformed NKPU unlock request packet" );

	auto kp = opt432->getData();
	if( kp.size() != 128 )
		isc_throw( Unexpected, "malformed NKPU unlock request packet" );

	auto kp2 = opt1251->getData();
	kp.insert( kp.end(), kp2.begin(), kp2.end() );
	if( kp.size() != 256 )
		isc_throw( Unexpected, "malformed NKPU unlock request packet" );

	if( response.getOption( DHO_VENDOR_ENCAPSULATED_OPTIONS ) != nullptr )
		return false;

	LOG_INFO( nkpu_logger, MSNKPU_PROCESS_REQUEST ).arg( query.getLabel() );

	auto kpd = DecryptRequest( kp, opt431->getData() );
	if( kpd.empty() || kpd.size() != 64 )
		isc_throw( Unexpected, "unlock request decryption failed" );

	//header + client key
	vector<uint8_t> buf;
	buf.insert( buf.end(), _header.begin(), _header.end() );
	buf.insert( buf.end(), kpd.begin(), kpd.begin() + 32 );

	//construct KPR with AES-CCM (encrypt hdr+clntkey w/ sesskey)
	array<uint8_t,16> mac;
	auto kpr = EncryptResponse( buf, vector<uint8_t>( kpd.begin() + 32, kpd.end() ), mac );
	if( kpr.empty() )
		isc_throw( Unexpected, "unlock response encryption failed" );

	//prepend with MAC
	kpr.insert( kpr.begin(), mac.begin(), mac.end() );

	auto r60 = boost::make_shared<Option>( Option::Universe::V4, DHO_VENDOR_CLASS_IDENTIFIER );
	response.addOption( r60 );
	string s60( "BITLOCKER" );
	r60->setData( s60.begin(), s60.end() );
	
	// KPR element
	auto r43 =  boost::make_shared<Option>( Option::Universe::V4, DHO_VENDOR_ENCAPSULATED_OPTIONS );
	response.addOption( r43 );

	auto r432 = boost::make_shared<Option>( Option::Universe::V4, 2 );
	r43->addOption( r432 );
	r432->setData( kpr.begin(), kpr.end() );

	response.delOption( DHO_DHCP_MESSAGE_TYPE );

	return true;
}

bool MsNkpu::Process( Pkt6& query, Pkt6& response )
{
	if( query.getType() != DHCPV6_INFORMATION_REQUEST )
		return true;

	bool f = false;
	for( auto o : query.getOptions( D6O_VENDOR_CLASS ) )
	{
		auto vc = dynamic_pointer_cast<OptionVendorClass>( o.second );
		if( !vc )
			continue;
		if( vc->getVendorId() != 311 )
			continue;
		if( !vc->hasTuple( "BITLOCKER" ) )
			continue;
		f = true;
		break;
	}
	if( !f )
		return true;

	OptionPtr vend1;
	OptionPtr vend2;
	for( auto o : query.getOptions( D6O_VENDOR_OPTS ) )
	{
		auto vc = dynamic_pointer_cast<OptionVendor>( o.second );
		if( !vc )
			continue;
		if( vc->getVendorId() != 311 )
			continue;
		vend1 = vc->getOption( 1 );
		vend2 = vc->getOption( 2 );
		break;
	}

	if( vend1 == nullptr )
		isc_throw( Unexpected, "malformed NKPU unlock request packet" );

	if( vend1->getData().size() != 20 )
		isc_throw( Unexpected, "malformed NKPU unlock request packet" );

	if( vend2 == nullptr )
		isc_throw( Unexpected, "malformed NKPU unlock request packet" );

	auto kp = vend2->getData();
	if( kp.size() != 256 )
		isc_throw( Unexpected, "malformed NKPU unlock request packet" );

	LOG_INFO( nkpu_logger, MSNKPU_PROCESS_REQUEST ).arg( query.getLabel() );

	auto kpd = DecryptRequest( kp, vend1->getData() );
	if( kpd.empty() || kpd.size() != 64 )
		isc_throw( Unexpected, "unlock request decryption failed" );

	//header + client key
	vector<uint8_t> buf;
	buf.insert( buf.end(), _header.begin(), _header.end() );
	buf.insert( buf.end(), kpd.begin(), kpd.begin() + 32 );

	//construct KPR with AES-CCM (encrypt hdr+clntkey w/ sesskey)
	array<uint8_t,16> mac;
	auto kpr = EncryptResponse( buf, vector<uint8_t>( kpd.begin() + 32, kpd.end() ), mac );
	if( kpr.empty() )
		isc_throw( Unexpected, "unlock response encryption failed" );

	//prepend with MAC
	kpr.insert( kpr.begin(), mac.begin(), mac.end() );

	auto vc = boost::make_shared<OptionVendorClass>( Option::Universe::V6, 311 );
	response.addOption( vc );
	OpaqueDataTuple bl( OpaqueDataTuple::LENGTH_2_BYTES );
	bl.append( "BITLOCKER" );
	vc->addTuple( bl );
	
	// KPR element
	auto vend =  boost::make_shared<OptionVendor>( Option::Universe::V6, 311 );
	response.addOption( vend );

	vend2 = boost::make_shared<Option>( Option::Universe::V6, 2 );
	vend->addOption( vend2 );
	vend2->setData( kpr.begin(), kpr.end() );

	return true;
}

static int password_cb(char *buf, int size, int rwflag, void *u)
{
	return -1;
}

const vector<uint8_t> MsNkpu::GetX509Digest( const string& path )
{
	FILE* fd = fopen( path.c_str(), "r" );
	if( fd == nullptr )
		isc_throw( BadValue, "loading X509 certificate from '" << path << "' failed" );

	auto x509 = PEM_read_X509( fd, nullptr, &password_cb, nullptr );
	fclose( fd );

	auto digest = EVP_get_digestbyname( "sha1" );
	vector<uint8_t> md( EVP_MAX_MD_SIZE );
	unsigned int len;
	X509_digest( x509, digest, md.data(), &len );
	md.resize( len );
	if( md.empty() )
		isc_throw( BadValue, "loading X509 certificate from '" << path << "' failed" );

	return md;
}

const EvpPkey MsNkpu::LoadPrivateKey( const string &path )
{
	FILE* fd = fopen( path.c_str(), "r" );
	if( fd == nullptr )
		isc_throw( BadValue, "loading RSA private key from '" << path << "' failed" );

	EvpPkey k( PEM_read_PrivateKey( fd, nullptr, &password_cb, nullptr ) );
	fclose( fd );
	return k;
}

vector<uint8_t> MsNkpu::DecryptRequest( const vector<uint8_t>& kp, const vector<uint8_t>& thumb )
{
	auto pk = _unlockKeys.find( thumb );
	if( pk == _unlockKeys.end() )
	{
		LOG_INFO( nkpu_logger, MSNKPU_PROCESS_NOPKEY ).arg( encode::encodeHex( thumb ) );
		return vector<uint8_t>();
	}

	unique_ptr<EVP_PKEY_CTX, void(*)(EVP_PKEY_CTX*)> c( EVP_PKEY_CTX_new( (*pk).second, nullptr ), &EVP_PKEY_CTX_free );
	if( !c )
		return vector<uint8_t>();

	if( EVP_PKEY_decrypt_init( c.get() ) <= 0 )
		return vector<uint8_t>();

	if( EVP_PKEY_CTX_set_rsa_padding( c.get(), RSA_PKCS1_PADDING ) <= 0 )
		return vector<uint8_t>();

	size_t len;
	if( EVP_PKEY_decrypt( c.get(), NULL, &len, kp.data(), kp.size() ) <= 0 )
		return vector<uint8_t>();

	vector<uint8_t> rsp( len );
	if( EVP_PKEY_decrypt( c.get(), rsp.data(), &len, kp.data(), kp.size() ) <= 0 )
		return vector<uint8_t>();

	rsp.resize( len );
	return rsp;
}

vector<uint8_t> MsNkpu::EncryptResponse( const vector<uint8_t>& msg, const vector<uint8_t>& key, array<uint8_t,16>& mac )
{
	unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)> c( EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free );
	auto ctx = c.get();
	if( ctx == nullptr )
		return vector<uint8_t>();
	EVP_CIPHER_CTX_init( ctx );

	// set cipher type and mode
	if( EVP_EncryptInit_ex( ctx, EVP_aes_256_ccm(), NULL, NULL, NULL ) <= 0 )
		return vector<uint8_t>();

	// set nonce length
	if( EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_CCM_SET_IVLEN, _nonce.size(), NULL ) <= 0 )
		return vector<uint8_t>();
 
	// set MAC length
	if( EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_CCM_SET_TAG, mac.size(), NULL ) <= 0 )
		return vector<uint8_t>();

	// initialise key and nonce
	if( EVP_EncryptInit_ex( ctx, NULL, NULL, key.data(), _nonce.data() ) <= 0 )
		return vector<uint8_t>();

	// create the buffer to hold the encrypted data,
	// add AES blocksize of 16 to allow for rounding
	int l = msg.size() + EVP_CIPHER_CTX_block_size( ctx );
	vector<uint8_t> txt( l );

	// encrypt plaintext (can only be called once!)
	if( EVP_EncryptUpdate( ctx, txt.data(), &l, msg.data(), msg.size() ) <= 0 )
		return vector<uint8_t>();

	// finalise the encryption process
	int tmp;
	if( EVP_EncryptFinal_ex( ctx, txt.data(), &tmp ) <= 0 )
		return vector<uint8_t>();

	txt.resize( l );

	// get the MAC
	if( EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_CCM_GET_TAG, mac.size(), mac.data() ) <= 0 ) 
		return vector<uint8_t>();

	return txt;
}

} } // namespace
