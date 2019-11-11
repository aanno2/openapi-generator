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



#include "User.h"

#include <string>
#include <sstream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

using boost::property_tree::ptree;
using boost::property_tree::read_json;
using boost::property_tree::write_json;

namespace org {
namespace openapitools {
namespace server {
namespace model {

User::User()
{
    m_Id = 0L;
    m_Username = "";
    m_FirstName = "";
    m_LastName = "";
    m_Email = "";
    m_Password = "";
    m_Phone = "";
    m_UserStatus = 0;
    
}

User::~User()
{
}

std::string User::toJsonString()
{
	std::stringstream ss;
	ptree pt;
	pt.put("id", m_Id);
	pt.put("username", m_Username);
	pt.put("firstName", m_FirstName);
	pt.put("lastName", m_LastName);
	pt.put("email", m_Email);
	pt.put("password", m_Password);
	pt.put("phone", m_Phone);
	pt.put("userStatus", m_UserStatus);
	write_json(ss, pt, false);
	return ss.str();
}

void User::fromJsonString(std::string const& jsonString)
{
	std::stringstream ss(jsonString);
	ptree pt;
	read_json(ss,pt);
	m_Id = pt.get("id", 0L);
	m_Username = pt.get("username", "");
	m_FirstName = pt.get("firstName", "");
	m_LastName = pt.get("lastName", "");
	m_Email = pt.get("email", "");
	m_Password = pt.get("password", "");
	m_Phone = pt.get("phone", "");
	m_UserStatus = pt.get("userStatus", 0);
}

int64_t User::getId() const
{
    return m_Id;
}
void User::setId(int64_t value)
{
    m_Id = value;
}
std::string User::getUsername() const
{
    return m_Username;
}
void User::setUsername(std::string value)
{
    m_Username = value;
}
std::string User::getFirstName() const
{
    return m_FirstName;
}
void User::setFirstName(std::string value)
{
    m_FirstName = value;
}
std::string User::getLastName() const
{
    return m_LastName;
}
void User::setLastName(std::string value)
{
    m_LastName = value;
}
std::string User::getEmail() const
{
    return m_Email;
}
void User::setEmail(std::string value)
{
    m_Email = value;
}
std::string User::getPassword() const
{
    return m_Password;
}
void User::setPassword(std::string value)
{
    m_Password = value;
}
std::string User::getPhone() const
{
    return m_Phone;
}
void User::setPhone(std::string value)
{
    m_Phone = value;
}
int32_t User::getUserStatus() const
{
    return m_UserStatus;
}
void User::setUserStatus(int32_t value)
{
    m_UserStatus = value;
}

}
}
}
}

