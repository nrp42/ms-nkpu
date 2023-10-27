#include <config.h>

#include "ms-nkpu.h"
#include "ms-nkpu-log.h"
#include <cc/command_interpreter.h>
#include <hooks/hooks.h>

namespace nrp { namespace ms_nkpu {

MsNkpu impl;

} } // namespace

using namespace isc;
using namespace isc::data;
using namespace isc::dhcp;
using namespace isc::hooks;
using namespace nrp::ms_nkpu;

extern "C"
{

int version() { return KEA_HOOKS_VERSION; }

int multi_threading_compatible() { return 1; }

int load( LibraryHandle& handle )
{
	try
	{
		impl.Reset();
		impl.Configure( handle.getParameter( "unlock-keys" ) );
	}
	catch( const std::exception& x )
	{
		LOG_ERROR( nkpu_logger, MSNKPU_LOAD_ERROR ).arg( x.what() );
		return 1;
	}

	return 0;
}

int unload()
{
	impl.Reset();
	LOG_INFO( nkpu_logger, MSNKPU_UNLOAD );
	return 0;
}

int buffer4_receive( CalloutHandle& handle )
{
	auto status = handle.getStatus();
	if( status == CalloutHandle::NEXT_STEP_DROP )
		return 0;

	Pkt4Ptr query;
	handle.getArgument( "query4", query );

	try
	{
		if( status != CalloutHandle::NEXT_STEP_SKIP )
		{
			query->unpack();
			handle.setStatus( CalloutHandle::NEXT_STEP_SKIP );
		}

		impl.PreProcess( *query );
	}
	catch( const exception &x )
	{
		LOG_ERROR( nkpu_logger, MSNKPU_PROCESS_ERROR ).arg( query->getLabel() ).arg( x.what() );
		handle.setStatus( CalloutHandle::NEXT_STEP_DROP );
	}

	return 0;
}

int pkt4_send(CalloutHandle & handle)
{
	auto status = handle.getStatus();
	if( status == CalloutHandle::NEXT_STEP_DROP )
		return 0;

	Pkt4Ptr query;
	Pkt4Ptr response;
	handle.getArgument( "query4", query );
	handle.getArgument( "response4", response );

	if( status == CalloutHandle::NEXT_STEP_SKIP )
		isc_throw( InvalidOperation, "packet pack already handled" );

	try
	{
		if( impl.Process( *query, *response ) )
			return 0;
	}
	catch( const std::exception &x )
	{
		LOG_ERROR( nkpu_logger, MSNKPU_PROCESS_ERROR ).arg( query->getLabel() ).arg( x.what() );
	}

	LOG_ERROR( nkpu_logger, MSNKPU_PROCESS_ERROR ).arg( query->getLabel() ).arg( "couldn't handle unlock request" );
	handle.setStatus( CalloutHandle::NEXT_STEP_DROP );

	return 0;
}

int pkt6_send(CalloutHandle & handle)
{
	auto status = handle.getStatus();
	if( status == CalloutHandle::NEXT_STEP_DROP )
		return 0;

	if( status == CalloutHandle::NEXT_STEP_SKIP )
		isc_throw( InvalidOperation, "packet pack already handled" );

	Pkt6Ptr query;
	Pkt6Ptr response;
	handle.getArgument( "query6", query );
	handle.getArgument( "response6", response );

	try
	{
		if( impl.Process( *query, *response ) )
			return 0;
	}
	catch (const std::exception &ex)
	{
		LOG_ERROR(nkpu_logger, MSNKPU_PROCESS_ERROR).arg(query->getLabel()).arg(ex.what());
	}

	LOG_ERROR( nkpu_logger, MSNKPU_PROCESS_ERROR ).arg( query->getLabel() ).arg( "couldn't handle unlock request" );
	handle.setStatus( CalloutHandle::NEXT_STEP_DROP );

	return 0;
}

} // end extern "C"
