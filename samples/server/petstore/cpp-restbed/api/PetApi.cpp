/**
 * OpenAPI Petstore
 * This is a sample server Petstore server. For this sample, you can use the api key `special-key` to test the authorization filters.
 *
 * The version of the OpenAPI document: 1.0.0
 * 
 *
 * NOTE: This class is auto generated by OpenAPI-Generator 4.2.1-SNAPSHOT.
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


#include <corvusoft/restbed/byte.hpp>
#include <corvusoft/restbed/string.hpp>
#include <corvusoft/restbed/settings.hpp>
#include <corvusoft/restbed/request.hpp>

#include "PetApi.h"

namespace org {
namespace openapitools {
namespace server {
namespace api {

using namespace org::openapitools::server::model;

PetApi::PetApi() {
	std::shared_ptr<PetApiPetResource> spPetApiPetResource = std::make_shared<PetApiPetResource>();
	this->publish(spPetApiPetResource);
	
	std::shared_ptr<PetApiPetPetIdResource> spPetApiPetPetIdResource = std::make_shared<PetApiPetPetIdResource>();
	this->publish(spPetApiPetPetIdResource);
	
	std::shared_ptr<PetApiPetFindByStatusResource> spPetApiPetFindByStatusResource = std::make_shared<PetApiPetFindByStatusResource>();
	this->publish(spPetApiPetFindByStatusResource);
	
	std::shared_ptr<PetApiPetFindByTagsResource> spPetApiPetFindByTagsResource = std::make_shared<PetApiPetFindByTagsResource>();
	this->publish(spPetApiPetFindByTagsResource);
	
	std::shared_ptr<PetApiPetPetIdUploadImageResource> spPetApiPetPetIdUploadImageResource = std::make_shared<PetApiPetPetIdUploadImageResource>();
	this->publish(spPetApiPetPetIdUploadImageResource);
	
}

PetApi::~PetApi() {}

void PetApi::startService(int const& port) {
	std::shared_ptr<restbed::Settings> settings = std::make_shared<restbed::Settings>();
	settings->set_port(port);
	settings->set_root("/v2");
	
	this->start(settings);
}

void PetApi::stopService() {
	this->stop();
}

PetApiPetResource::PetApiPetResource()
{
	this->set_path("/pet/");
	this->set_method_handler("POST",
		std::bind(&PetApiPetResource::POST_method_handler, this,
			std::placeholders::_1));
	this->set_method_handler("PUT",
		std::bind(&PetApiPetResource::PUT_method_handler, this,
			std::placeholders::_1));
}

PetApiPetResource::~PetApiPetResource()
{
}

void PetApiPetResource::set_handler_POST(
	std::function<std::pair<int, std::string>(
		std::shared_ptr<Pet> const &
	)> handler) {
	handler_POST_ = std::move(handler);
}

void PetApiPetResource::set_handler_PUT(
	std::function<std::pair<int, std::string>(
		std::shared_ptr<Pet> const &
	)> handler) {
	handler_PUT_ = std::move(handler);
}

void PetApiPetResource::POST_method_handler(const std::shared_ptr<restbed::Session> session) {

	const auto request = session->get_request();
	// Body params are present, therefore we have to fetch them
	int content_length = request->get_header("Content-Length", 0);
	session->fetch(content_length,
		[ this ]( const std::shared_ptr<restbed::Session> session, const restbed::Bytes & body )
		{

			const auto request = session->get_request();
			std::string file = restbed::String::format("%.*s\n", ( int ) body.size( ), body.data( ));
			/**
			 * Get body params or form params here from the file string
			 */




			// Change the value of this variable to the appropriate response before sending the response
			int status_code = 200;
			std::string result = "successful operation";

			if (handler_POST_)
			{
				std::tie(status_code, result) = handler_POST_(
					body
				);
			}

			if (status_code == 405) {
				session->close(405, result.empty() ? "Invalid input" : std::move(result), { {"Connection", "close"} });
				return;
			}

		});
}

void PetApiPetResource::PUT_method_handler(const std::shared_ptr<restbed::Session> session) {

	const auto request = session->get_request();
	// Body params are present, therefore we have to fetch them
	int content_length = request->get_header("Content-Length", 0);
	session->fetch(content_length,
		[ this ]( const std::shared_ptr<restbed::Session> session, const restbed::Bytes & body )
		{

			const auto request = session->get_request();
			std::string file = restbed::String::format("%.*s\n", ( int ) body.size( ), body.data( ));




			// Change the value of this variable to the appropriate response before sending the response
			int status_code = 200;
			std::string result = "successful operation";

			if (handler_PUT_)
			{
				std::tie(status_code, result) = handler_PUT_(
					body
				);
			}

			if (status_code == 400) {
				session->close(400, result.empty() ? "Invalid ID supplied" : std::move(result), { {"Connection", "close"} });
				return;
			}
			if (status_code == 404) {
				session->close(404, result.empty() ? "Pet not found" : std::move(result), { {"Connection", "close"} });
				return;
			}
			if (status_code == 405) {
				session->close(405, result.empty() ? "Validation exception" : std::move(result), { {"Connection", "close"} });
				return;
			}

		});
}


PetApiPetPetIdResource::PetApiPetPetIdResource()
{
	this->set_path("/pet/{petId: .*}/");
	this->set_method_handler("DELETE",
		std::bind(&PetApiPetPetIdResource::DELETE_method_handler, this,
			std::placeholders::_1));
	this->set_method_handler("GET",
		std::bind(&PetApiPetPetIdResource::GET_method_handler, this,
			std::placeholders::_1));
	this->set_method_handler("POST",
		std::bind(&PetApiPetPetIdResource::POST_method_handler, this,
			std::placeholders::_1));
}

PetApiPetPetIdResource::~PetApiPetPetIdResource()
{
}

void PetApiPetPetIdResource::set_handler_DELETE(
	std::function<std::pair<int, std::string>(
		int64_t const &, std::string const &
	)> handler) {
	handler_DELETE_ = std::move(handler);
}

void PetApiPetPetIdResource::set_handler_GET(
	std::function<std::pair<int, std::string>(
		int64_t const &
	)> handler) {
	handler_GET_ = std::move(handler);
}
void PetApiPetPetIdResource::set_handler_POST(
	std::function<std::pair<int, std::string>(
		int64_t const &, std::string const &, std::string const &
	)> handler) {
	handler_POST_ = std::move(handler);
}

void PetApiPetPetIdResource::DELETE_method_handler(const std::shared_ptr<restbed::Session> session) {

	const auto request = session->get_request();

			// Getting the path params
			const int64_t petId = request->get_path_parameter("petId", 0L);


			// Getting the headers
			const std::string apiKey = request->get_header("apiKey", "");

			// Change the value of this variable to the appropriate response before sending the response
			int status_code = 200;
			std::string result = "successful operation";

			if (handler_DELETE_)
			{
				std::tie(status_code, result) = handler_DELETE_(
					petId, apiKey
				);
			}

			if (status_code == 400) {
				session->close(400, result.empty() ? "Invalid pet value" : std::move(result), { {"Connection", "close"} });
				return;
			}

}

void PetApiPetPetIdResource::GET_method_handler(const std::shared_ptr<restbed::Session> session) {

	const auto request = session->get_request();

			// Getting the path params
			const int64_t petId = request->get_path_parameter("petId", 0L);



			// Change the value of this variable to the appropriate response before sending the response
			int status_code = 200;
			std::string result = "successful operation";

			if (handler_GET_)
			{
				std::tie(status_code, result) = handler_GET_(
					petId
				);
			}

			if (status_code == 200) {
				std::shared_ptr<Pet> response = NULL;
				session->close(200, result.empty() ? "successful operation" : std::move(result), { {"Connection", "close"} });
				return;
			}
			if (status_code == 400) {
				session->close(400, result.empty() ? "Invalid ID supplied" : std::move(result), { {"Connection", "close"} });
				return;
			}
			if (status_code == 404) {
				session->close(404, result.empty() ? "Pet not found" : std::move(result), { {"Connection", "close"} });
				return;
			}

}
void PetApiPetPetIdResource::POST_method_handler(const std::shared_ptr<restbed::Session> session) {

	const auto request = session->get_request();

			// Getting the path params
			const int64_t petId = request->get_path_parameter("petId", 0L);



			// Change the value of this variable to the appropriate response before sending the response
			int status_code = 200;
			std::string result = "successful operation";

			if (handler_POST_)
			{
				std::tie(status_code, result) = handler_POST_(
					petId, name, status
				);
			}

			if (status_code == 405) {
				session->close(405, result.empty() ? "Invalid input" : std::move(result), { {"Connection", "close"} });
				return;
			}

}


PetApiPetFindByStatusResource::PetApiPetFindByStatusResource()
{
	this->set_path("/pet/findByStatus/");
	this->set_method_handler("GET",
		std::bind(&PetApiPetFindByStatusResource::GET_method_handler, this,
			std::placeholders::_1));
}

PetApiPetFindByStatusResource::~PetApiPetFindByStatusResource()
{
}

void PetApiPetFindByStatusResource::set_handler_GET(
	std::function<std::pair<int, std::string>(
		std::vector<std::string> const &
	)> handler) {
	handler_GET_ = std::move(handler);
}


void PetApiPetFindByStatusResource::GET_method_handler(const std::shared_ptr<restbed::Session> session) {

	const auto request = session->get_request();


			// Getting the query params


			// Change the value of this variable to the appropriate response before sending the response
			int status_code = 200;
			std::string result = "successful operation";

			if (handler_GET_)
			{
				std::tie(status_code, result) = handler_GET_(
					status
				);
			}

			if (status_code == 200) {
				session->close(200, result.empty() ? "successful operation" : std::move(result), { {"Connection", "close"} });
				return;
			}
			if (status_code == 400) {
				session->close(400, result.empty() ? "Invalid status value" : std::move(result), { {"Connection", "close"} });
				return;
			}

}



PetApiPetFindByTagsResource::PetApiPetFindByTagsResource()
{
	this->set_path("/pet/findByTags/");
	this->set_method_handler("GET",
		std::bind(&PetApiPetFindByTagsResource::GET_method_handler, this,
			std::placeholders::_1));
}

PetApiPetFindByTagsResource::~PetApiPetFindByTagsResource()
{
}

void PetApiPetFindByTagsResource::set_handler_GET(
	std::function<std::pair<int, std::string>(
		std::vector<std::string> const &
	)> handler) {
	handler_GET_ = std::move(handler);
}


void PetApiPetFindByTagsResource::GET_method_handler(const std::shared_ptr<restbed::Session> session) {

	const auto request = session->get_request();


			// Getting the query params


			// Change the value of this variable to the appropriate response before sending the response
			int status_code = 200;
			std::string result = "successful operation";

			if (handler_GET_)
			{
				std::tie(status_code, result) = handler_GET_(
					tags
				);
			}

			if (status_code == 200) {
				session->close(200, result.empty() ? "successful operation" : std::move(result), { {"Connection", "close"} });
				return;
			}
			if (status_code == 400) {
				session->close(400, result.empty() ? "Invalid tag value" : std::move(result), { {"Connection", "close"} });
				return;
			}

}



PetApiPetPetIdUploadImageResource::PetApiPetPetIdUploadImageResource()
{
	this->set_path("/pet/{petId: .*}/uploadImage/");
	this->set_method_handler("POST",
		std::bind(&PetApiPetPetIdUploadImageResource::POST_method_handler, this,
			std::placeholders::_1));
}

PetApiPetPetIdUploadImageResource::~PetApiPetPetIdUploadImageResource()
{
}

void PetApiPetPetIdUploadImageResource::set_handler_POST(
	std::function<std::pair<int, std::string>(
		int64_t const &, std::string const &, std::string const &
	)> handler) {
	handler_POST_ = std::move(handler);
}


void PetApiPetPetIdUploadImageResource::POST_method_handler(const std::shared_ptr<restbed::Session> session) {

	const auto request = session->get_request();

			// Getting the path params
			const int64_t petId = request->get_path_parameter("petId", 0L);



			// Change the value of this variable to the appropriate response before sending the response
			int status_code = 200;
			std::string result = "successful operation";

			if (handler_POST_)
			{
				std::tie(status_code, result) = handler_POST_(
					petId, additionalMetadata, file
				);
			}

			if (status_code == 200) {
				session->close(200, result.empty() ? "successful operation" : std::move(result), { {"Connection", "close"} });
				return;
			}

}




}
}
}
}

