/**
 * OpenAPI Petstore
 * This is a sample server Petstore server. For this sample, you can use the api key `special-key` to test the authorization filters.
 *
 * The version of the OpenAPI document: 1.0.0
 *
 * NOTE: This class is auto generated by OpenAPI-Generator 4.2.1-SNAPSHOT.
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

/*
 * HttpContent.h
 *
 * This class represents a single item of a multipart-formdata request.
 */

#ifndef ORG_OPENAPITOOLS_CLIENT_MODEL_HttpContent_H_
#define ORG_OPENAPITOOLS_CLIENT_MODEL_HttpContent_H_



#include <memory>

#include <cpprest/details/basic_types.h>

namespace org {
namespace openapitools {
namespace client {
namespace model {

class  HttpContent
{
public:
    HttpContent();
    virtual ~HttpContent();

    virtual utility::string_t getContentDisposition();
    virtual void setContentDisposition( const utility::string_t& value );

    virtual utility::string_t getName();
    virtual void setName( const utility::string_t& value );

    virtual utility::string_t getFileName();
    virtual void setFileName( const utility::string_t& value );

    virtual utility::string_t getContentType();
    virtual void setContentType( const utility::string_t& value );

    virtual std::shared_ptr<std::istream> getData();
    virtual void setData( std::shared_ptr<std::istream> value );

    virtual void writeTo( std::ostream& stream );

protected:
    // NOTE: no utility::string_t here because those strings can only contain ascii
    utility::string_t m_ContentDisposition;
    utility::string_t m_Name;
    utility::string_t m_FileName;
    utility::string_t m_ContentType;
    std::shared_ptr<std::istream> m_Data;
};

}
}
}
}

#endif /* ORG_OPENAPITOOLS_CLIENT_MODEL_HttpContent_H_ */
