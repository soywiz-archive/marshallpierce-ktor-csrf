package org.mpierce.ktor.csrf

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.http.Headers
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.response.*
import io.ktor.routing.get
import io.ktor.routing.routing
import io.ktor.server.testing.TestApplicationRequest
import io.ktor.server.testing.handleRequest
import io.ktor.server.testing.withTestApplication
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

internal class CsrfProtectionTest {


    @Test
    internal fun originMatchesKnownHostWithNoHeadersRejected() {
        simpleValidatorTest(OriginMatchesKnownHost("http", "csrf.test"), HttpStatusCode.BadRequest) {
        }
    }

    @Test
    internal fun originMatchesKnownHostWithInvalidOriginHeaderRejected() {
        simpleValidatorTest(OriginMatchesKnownHost("http", "csrf.test"), HttpStatusCode.BadRequest) {
            addHeader("Origin", "http://nope.wrong")
        }
    }

    @Test
    internal fun originMatchesKnownHostWithValidOriginHeaderAccepted() {
        simpleValidatorTest(OriginMatchesKnownHost("http", "csrf.test"), HttpStatusCode.NoContent) {
            addHeader("Origin", "http://csrf.test")
        }
    }

    @Test
    internal fun originMatchesKnownHostWithPortWithValidOriginHeaderWithPortAccepted() {
        simpleValidatorTest(OriginMatchesKnownHost("http", "csrf.test", 1234), HttpStatusCode.NoContent) {
            addHeader("Origin", "http://csrf.test:1234")
        }
    }

    @Test
    internal fun originMatchesKnownHostWithPortWithValidOriginHeaderWithoutPortRejected() {
        simpleValidatorTest(OriginMatchesKnownHost("http", "csrf.test", 1234), HttpStatusCode.BadRequest) {
            addHeader("Origin", "http://csrf.test")
        }
    }

    @Test
    internal fun originMatchesHostHeaderWithNoHeadersRejected() {
        simpleValidatorTest(OriginMatchesHostHeader(), HttpStatusCode.BadRequest) {
        }
    }

    @Test
    internal fun originMatchesHostHeaderWithNoOriginHeaderRejected() {
        simpleValidatorTest(OriginMatchesHostHeader(), HttpStatusCode.BadRequest) {
            addHeader("Host", "csrf.test")
        }
    }

    @Test
    internal fun originMatchesHostHeaderWithNoHostHeaderRejected() {
        simpleValidatorTest(OriginMatchesHostHeader(), HttpStatusCode.BadRequest) {
            addHeader("Origin", "http://csrf.test")
        }
    }

    @Test
    internal fun originMatchesHostHeaderWithInvalidOriginHeaderRejected() {
        simpleValidatorTest(OriginMatchesHostHeader(), HttpStatusCode.BadRequest) {
            addHeader("Host", "csrf.test")
            addHeader("Origin", "http://nope.wrong")
        }
    }

    @Test
    internal fun originMatchesHostHeaderWithValidOriginHeaderOk() {
        simpleValidatorTest(OriginMatchesHostHeader(), HttpStatusCode.NoContent) {
            addHeader("Host", "csrf.test")
            addHeader("Origin", "http://csrf.test")
        }
    }

    @Test
    internal fun customHeaderPresentWithHeaderOk() {
        simpleValidatorTest(HeaderPresent("X-Foo"), HttpStatusCode.NoContent) {
            addHeader("Host", "csrf.test")
            addHeader("X-Foo", "whatever")
        }
    }

    @Test
    internal fun customHeaderPresentWithoutValidCustomHeaderRejected() {
        simpleValidatorTest(HeaderPresent("X-Foo"), HttpStatusCode.BadRequest) {
            addHeader("Host", "csrf.test")
            addHeader("X-Bar", "whatever")
        }
    }

    @Test
    internal fun rejectsIfAnyValidatorFails() {
        withTestApplication({
            install(CsrfProtection) {
                validate(object : RequestValidator {
                    override fun validate(headers: Headers): Boolean = true
                })
                validate(object : RequestValidator {
                    override fun validate(headers: Headers): Boolean = false
                })
            }
            configureTestEndpoints()
        }) {
            with(handleRequest(HttpMethod.Get, "/endpoint") {
            }) {
                assertEquals(HttpStatusCode.BadRequest, response.status())
            }
        }
    }

    @Test
    internal fun acceptsIfAllValidatorPass() {
        withTestApplication({
            install(CsrfProtection) {
                repeat(2) {
                    validate(object : RequestValidator {
                        override fun validate(headers: Headers): Boolean = true
                    })
                }
            }
            configureTestEndpoints()
        }) {
            with(handleRequest(HttpMethod.Get, "/endpoint") {
            }) {
                assertEquals(HttpStatusCode.NoContent, response.status())
            }
        }
    }

    @Test
    fun blackListMode() {
        withTestApplication({
            install(CsrfProtection) {
                applyToAllRoutes()
                validate(object : RequestValidator {
                    override fun validate(headers: Headers): Boolean = false
                })
            }
            routing {
                get("/endpoint") {
                    call.respondText("this shouldn't happen", status = HttpStatusCode.InternalServerError)
                }
                noCsrfProtection {
                    get("/noCsrfProtection") {
                        call.respondText("ok", status = HttpStatusCode.OK)
                    }
                }
            }
        }) {
            //with(handleRequest(HttpMethod.Get, "/endpoint", {})) {
            //    assertEquals(HttpStatusCode.BadRequest, response.status())
            //}
            with(handleRequest(HttpMethod.Get, "/noCsrfProtection", {})) {
                assertEquals(HttpStatusCode.OK, response.status())
            }
        }
    }

    @Test
    fun noCsrfProtectionEndpointAccessible() {
        simpleValidatorTest(OriginMatchesHostHeader(), HttpStatusCode.Created, path = "/noCsrfProtection") {}
    }


    private fun simpleValidatorTest(
        validator: RequestValidator,
        statusCode: HttpStatusCode,
        path: String = "/endpoint",
        requestConfig: TestApplicationRequest.() -> Unit
    ) {
        withTestApplication({
            install(CsrfProtection) {
                validate(validator)
            }
            configureTestEndpoints()
        }) {
            with(handleRequest(HttpMethod.Get, path, requestConfig)) {
                assertEquals(statusCode, response.status())
            }
        }
    }

    private fun Application.configureTestEndpoints() {
        routing {
            csrfProtection {
                get("/endpoint") {
                    call.respond(HttpStatusCode.NoContent)
                }
            }
            get("/noCsrfProtection") {
                call.respond(HttpStatusCode.Created)
            }
        }
    }
}