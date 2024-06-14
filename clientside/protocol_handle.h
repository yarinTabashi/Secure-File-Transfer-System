#pragma once
#include "protocol.h"
#include <boost/asio.hpp>

#define DEFAULT_PROTOCOL_NUM (3)

class ProtocolHandle
{
private:
	template <typename T>
	union _SocketData
	{
		unsigned char as_buffer[sizeof(T)];
		T as_original;
	};

public:
	template <class T>
	static T generate_request(RequestId req_id, u_char user_id[CLIENT_ID_LENGTH])
	{
		static_assert(std::is_base_of<RequestHeader, T>::value, "T must inherit from ClientRequestBase!");

		T req{};
		req.version = DEFAULT_PROTOCOL_NUM;
		req.req_id = req_id;

		std::memcpy(&req.user_id, user_id, CLIENT_ID_LENGTH);

		req.payload_size = sizeof(T) - sizeof(RequestHeader);

		return req;
	}

	template <typename T>
	static void recieve_response(T* response, boost::asio::ip::tcp::socket& socket, size_t length)
	{
		unsigned char* temp = reinterpret_cast<unsigned char*>(response);
		boost::asio::read(socket, boost::asio::buffer(temp, length));
	}


	template <typename T>
	static void recieve_static(T* dest_data,
		boost::asio::ip::tcp::socket& src) {
		auto* dest = (_SocketData<T>*)dest_data;
		boost::asio::read(src, boost::asio::buffer(dest->as_buffer, sizeof(dest->as_buffer)));
	}

	// It used to read the symetric key, because it's size is known just in runtime.
	template <typename T>
	static void recieve_additional(T* dest_data, boost::asio::ip::tcp::socket& src,size_t read_count) 
	{
		unsigned char* temp = (unsigned char*)dest_data;
		boost::asio::read(src, boost::asio::buffer(temp, read_count));
	}


	template <typename T>
	static void send_request(T* request, boost::asio::ip::tcp::socket& dest)
	{
		auto src = (_SocketData<T>*)request;
		boost::asio::write(dest, boost::asio::buffer(src->as_buffer, sizeof(src->as_buffer)));
	}
};
