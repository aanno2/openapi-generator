package model

import play.api.libs.json._

/**
  * A tag for a pet
  */
@javax.annotation.Generated(value = Array("org.openapitools.codegen.languages.ScalaPlayFrameworkServerCodegen"), date = "2019-11-11T13:44:17.651+01:00[Europe/Berlin]")
case class Tag(
  id: Option[Long],
  name: Option[String]
)

object Tag {
  implicit lazy val tagJsonFormat: Format[Tag] = Json.format[Tag]
}

