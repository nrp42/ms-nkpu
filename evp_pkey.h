#ifndef MS_NKPU_EVP_PKEY_H
#define MS_NKPU_EVP_PKEY_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/types.h>


namespace nrp { namespace ms_nkpu {

class EvpPkey
{
public:
	EvpPkey( EVP_PKEY* pk )
		: _pk( pk )
	{ };

	EvpPkey( const EvpPkey& other )
		: _pk( other._pk )
	{ 
		if( _pk != nullptr )
			EVP_PKEY_up_ref( _pk );
	};

	~EvpPkey()
	{
		if( _pk != nullptr )
			EVP_PKEY_free( _pk );
	}

	operator EVP_PKEY*() const
	{
		return _pk;
	}

private:
	EVP_PKEY* _pk;
};

} } // end of namespaces

#endif
