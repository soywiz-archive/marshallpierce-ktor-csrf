package org.mpierce.ktor.csrf

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.http.Headers
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.response.respond
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
    internal fun customHeaderPresentWithoutHeaderRejected() {
        simpleValidatorTest(HeaderPresent("X-Foo"), HttpStatusCode.BadRequest) {
            addHeader("Host", "csrf.test")
            addHeader("X-Bar", "whatever")
        }
    }

    @Test
    internal fun rejectsIfAnyValidatorFails() {
        withTestApplication({
            configureTestEndpoints()
            install(CsrfProtection) {
                validate(object : RequestValidator {
                    override fun validate(headers: Headers): Boolean = true
                })
                validate(object : RequestValidator {
                    override fun validate(headers: Headers): Boolean = false
                })
            }
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
            configureTestEndpoints()
            install(CsrfProtection) {
                repeat(2) {
                    validate(object : RequestValidator {
                        override fun validate(headers: Headers): Boolean = true
                    })
                }
            }
        }) {
            with(handleRequest(HttpMethod.Get, "/endpoint") {
            }) {
                assertEquals(HttpStatusCode.NoContent, response.status())
            }
        }
    }

    private fun simpleValidatorTest(validator: RequestValidator, statusCode: HttpStatusCode,
                                    requestConfig: TestApplicationRequest.() -> Unit) {
        withTestApplication({
            configureTestEndpoints()
            install(CsrfProtection) {
                validate(validator)
            }
        }) {
            with(handleRequest(HttpMethod.Get, "/endpoint", requestConfig)) {
                assertEquals(statusCode, response.status())
            }
        }
    }

    private fun Application.configureTestEndpoints() {
        routing {
            get("/endpoint") {
                call.respond(HttpStatusCode.NoContent)
            }
        }
    }

}
