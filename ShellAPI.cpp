#include "IShellAPI.h"
#include <array>
#include <stdexcept>
#include <memory>
#include <iostream>
#include <thread>

core::sint32_t IShell::exec(std::string* cmd) {
	std::array<char, 1024> buffer;
	std::string result;

	std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen((const char *)cmd->c_str(), "r"), _pclose);
	
	if (!pipe)
		return core::errors::ERROR_READ_STDOUT;

	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
		result += buffer.data();

	*cmd = result;

	return 0;
}

std::string IShell::cmd() {
	core::int32_t get_buffer = 0;

	std::string buffer;

	while (get_buffer != 10) {
		get_buffer = getchar();
		buffer.push_back(get_buffer);
	}

	return buffer;
}

std::string IShellAPI::_inet_ntoa(InAddr ip) {

}

void IShell::bytes_convert(void* src, void* dst, core::IShellAPI_types::socklen_t size) {
	if ((uintptr_t)src % sizeof(long) == 0 &&
		(uintptr_t)dst % sizeof(char) == 0) {
		long* _src = (long*)src;
		const char* _dst = (const char*)dst;

		for (core::IShellAPI_types::socklen_t i = 0; i < size; i++)
			*_src++ = *_dst++;
	}

	else if ((uintptr_t)src % sizeof(char) == 0 &&
		(uintptr_t)dst % sizeof(long) == 0) {
		core::int8_t* buffer = (core::int8_t*)src;
		long* _dst = (long*)dst;

		for (core::IShellAPI_types::socklen_t i = 0; i < size; i++)
			*buffer++ = *_dst++;
	}

	else {
		char* _src = (char*)src;
		const char* _dst = (const char*)dst;


		for (core::IShellAPI_types::socklen_t i = 0; i < size; i++)
			*_src++ = *_dst++;
	}
}

IShellAPI::IShellAPI(std::string &ip_address) {
	this->ip_address = ip_address;

	pkt_data = new pkt_data_t();

	pkt_data->sin_connect = new pkt_t[3];
	pkt_data->sin_socket = new core::IShellAPI_types::SOCKET[3];

	#ifdef _MSC_VER
		WSADATA wsa;

		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
			this->error_buffer = core::errors::ERROR_CREATE_WINSOCK_VER;
	#endif // _MSC_VER
}

IShellAPI::~IShellAPI() {
	for (core::IShellAPI_types::socklen_t i = 0; i < 3; i++)
		closesocket(pkt_data->sin_socket[i]);

	free(pkt_data->sin_connect);
	free(pkt_data->sin_socket);
}

core::sint32_t IShellAPI::init_socket(core::int32_t l4_pick) {
	pkt_data->sin_connect[1].sin_addr.in_addr = htonl(INADDR_ANY);
	pkt_data->sin_connect[1].sin_port		  = htons(core::port::port_accept);
	pkt_data->sin_connect[1].sin_family		  = AF_INET;
	// listening

	#ifdef _MSC_VER
		inet_pton(AF_INET, ip_address.c_str(), &pkt_data->sin_connect[0].sin_addr);
	#else
		pkt_data->sin_connect[0].sin_addr.in_addr  = inet_addr(ip_address.c_str());
	#endif // MSC_VER

	pkt_data->sin_connect[0].sin_port		  = htons(core::port::port_connect);
	pkt_data->sin_connect[0].sin_family		  = AF_INET;

	if (l4_pick == core::l4_proto_peak::tcp_peak) {
		pkt_data->sin_socket[1] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		pkt_data->sin_socket[0] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		#ifdef _MSC_VER
			if (pkt_data->sin_socket[0] == INVALID_SOCKET) {
				error_buffer = core::errors::ERROR_CREATE_SOCKET;

				return core::errors::ERROR_CREATE_SOCKET;
			}

			if (pkt_data->sin_socket[1] == INVALID_SOCKET) {
				error_buffer = core::errors::ERROR_CREATE_SOCKET;

				return core::errors::ERROR_CREATE_SOCKET;
			}
		#else
			if (pkt_data->sin_socket[0] < 0) {
				error_buffer = core::errors::ERROR_CREATE_SOCKET;

				return core::errors::ERROR_CREATE_SOCKET;
			}

			if (pkt_data->sin_socket[1] < 0) {
				error_buffer = core::errors::ERROR_CREATE_SOCKET;

				return core::errors::ERROR_CREATE_SOCKET;
		#endif // _MSC_VER
	}
}

core::int32_t IShellAPI::_bind(core::IShellAPI_types::SOCKET sock, _pkt_raw_t sock_raw, core::IShellAPI_types::socklen_t size_sock) {
	#ifdef _MSC_VER
		if (bind(sock, (sockaddr*)sock_raw, size_sock) == SOCKET_ERROR) {
			error_buffer = core::errors::ERROR_CREATE_BIND;

			return core::errors::ERROR_CREATE_BIND;
		}
	#else
		if (bind(sock, (sockaddr*)sock_raw, size_sock) < 0) {
			error_buffer = core::errors::ERROR_CREATE_BIND;

			return core::errors::ERROR_CREATE_BIND;
		}
	#endif // _MSC_VER

	return 0;
}

core::int32_t IShellAPI::_connect(core::IShellAPI_types::SOCKET sock, _pkt_raw_t sock_raw, core::IShellAPI_types::socklen_t sock_size) {
	#ifdef _MSC_VER
		if (connect(sock, (sockaddr*)sock_raw, sock_size) == SOCKET_ERROR) {
			error_buffer = core::errors::ERROR_CREATE_CONNECT;

			return core::errors::ERROR_CREATE_CONNECT;
		}
	#else
		if (connect(sock, (sockaddr*)sock_raw, sock_size) < 0) {
			error_buffer = core::errors::ERROR_CREATE_CONNECT;

			return core::errors::ERROR_CREATE_CONNECT;
		}
	#endif // _MSC_VER

	return 0;
}

core::IShellAPI_types::SOCKET IShellAPI::_accept(core::IShellAPI_types::SOCKET sock, _pkt_raw_t client_sock_raw, core::IShellAPI_types::socklen_t client_size_sock) {
	return accept(sock, (sockaddr *)client_sock_raw, &client_size_sock);
}

core::sint32_t IShellAPI::shell_client() {
	core::sint32_t buff_error;

	std::thread([&]() -> void {
		if (_bind(pkt_data->sin_socket[1], (_pkt_raw_t)&pkt_data->sin_connect[1], sizeof(pkt_data->sin_connect[1])))
			buff_error = core::errors::ERROR_CREATE_BIND;

		while (0x1) {
			if (listen(pkt_data->sin_socket[1], 0xff) < 0)
				buff_error = core::errors::ERROR_CREATE_LISTEN;
		
			pkt_data->sin_size		= sizeof(pkt_data->sin_connect[2]);
			pkt_data->sin_socket[2] = _accept(pkt_data->sin_socket[1], (_pkt_raw_t)&pkt_data->sin_connect[2], pkt_data->sin_size);

			//fprintf(stdout, "[INFO]Noticed new connection...\n<ip-address: %s>\n<port: %d\n>");

			#ifdef _MSC_VER
				if (pkt_data->sin_socket[2] == INVALID_SOCKET)
					buff_error = core::errors::ERROR_CREATE_SOCKET;
			#else
				if (pkt_data->sin_socket[2] < 0)
					buff_error = core::errors::ERROR_CREATE_SOCKET;
			#endif // _MSC_VER
		}
	}).detach();

	this->error_buffer = buff_error;
}