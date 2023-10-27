#ifndef MS_NKPU_H
#define MS_NKPU_H

#include <cc/data.h>
#include <cc/simple_parser.h>
#include <dhcp/classify.h>
#include <dhcp/libdhcp++.h>
#include <dhcp/option.h>
#include <dhcp/option_definition.h>
#include <dhcp/option_vendor.h>
#include <dhcp/std_option_defs.h>
#include <eval/evaluate.h>
#include <eval/token.h>
#include <util/strutil.h>
#include <dhcp/pkt4.h>
#include <dhcp/pkt6.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/types.h>

#include <map>
#include <string>

#include "evp_pkey.h"

namespace nrp { namespace ms_nkpu {

using namespace std;
using namespace isc;

class MsNkpu
{
public:
	MsNkpu()
		: _unlockKeys(), _nonce(),_header( { 0x2c, 0, 0, 0, 1, 0, 0, 0, 6, 0x20, 0, 0 } )
	{ };

	~MsNkpu();

	void Reset();

	void Configure( isc::data::ConstElementPtr options );

	void PreProcess( dhcp::Pkt4& query );

	bool Process( dhcp::Pkt4& query, dhcp::Pkt4& response );
	bool Process( dhcp::Pkt6& query, dhcp::Pkt6& response );

private:
	const vector<uint8_t> GetX509Digest( const string& path );
	const EvpPkey LoadPrivateKey( const string& path );
	vector<uint8_t> DecryptRequest( const vector<uint8_t>& kp, const vector<uint8_t>& thumb );
	vector<uint8_t> EncryptResponse( const vector<uint8_t>& msg, const vector<uint8_t>& key, array<uint8_t,16>& mac );

	static const string ParamKeys;
	static const string ParamCertFile;
	static const string ParamKeyFile;

	map<const vector<uint8_t>, const EvpPkey> _unlockKeys;
	const array<uint8_t,12> _header;
	const array<uint8_t,12> _nonce;
};

typedef boost::shared_ptr<MsNkpu> MsNkpuPtr;

} } // end of namespaces

#endif
