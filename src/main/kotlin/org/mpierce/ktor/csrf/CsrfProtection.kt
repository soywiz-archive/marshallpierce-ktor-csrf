package org.mpierce.ktor.csrf

import io.ktor.application.ApplicationCall
import io.ktor.application.ApplicationCallPipeline
import io.ktor.application.ApplicationFeature
import io.ktor.application.call
import io.ktor.http.Headers
import io.ktor.http.HttpStatusCode
import io.ktor.pipeline.PipelineContext
import io.ktor.pipeline.PipelinePhase
import io.ktor.response.respond
import io.ktor.util.AttributeKey
import java.net.MalformedURLException
import java.net.URL

/**
 * Ktor feature for CSRF protection.
 */
class CsrfProtection(config: Configuration) {
    private val validators = config.validators.toList()

    class Configuration {
        val validators = mutableListOf<RequestValidator>()
        /**
         * Validate the request headers with the provided validator.
         *
         * If called multiple times, all provided validators must pass to approve a request.
         */
        fun validate(rv: RequestValidator) {
            validators.add(rv)
        }
    }

    private suspend fun intercept(context: PipelineContext<Unit, ApplicationCall>) {
        if (validators.any { !it.validate(context.call.request.headers) }) {
            context.call.respond(HttpStatusCode.BadRequest)
            context.finish()
        }
    }

    companion object Feature : ApplicationFeature<ApplicationCallPipeline, Configuration, CsrfProtection> {
        override val key = AttributeKey<CsrfProtection>("CsrfPrevention")
        override fun install(pipeline: ApplicationCallPipeline, configure: Configuration.() -> Unit): CsrfProtection {
            val config = Configuration().apply(configure)
            val feature = CsrfProtection(config)

            val phase = PipelinePhase("CsrfPrevention")
            pipeline.insertPhaseAfter(ApplicationCallPipeline.Infrastructure, phase)

            pipeline.intercept(phase) {
                feature.intercept(this)
            }

            return feature
        }
    }
}

interface RequestValidator {
    fun validate(headers: Headers): Boolean
}

/**
 * Validates that Origin matches a specific host (presumably, the host that this service is deployed at).
 *
 * If port is unspecified here, the urls in the headers will match only if they don't have a port specified either.
 */
class OriginMatchesKnownHost(scheme: String, host: String, port: Int? = null) : RequestValidator {
    private val host = HostTuple(scheme, host, port)

    override fun validate(headers: Headers): Boolean {
        val origin = headerUrl(headers, "Origin") ?: return false

        return host.matches(origin)
    }
}

/**
 * Validates that the Origin header matches the host specified in the Host header.
 */
class OriginMatchesHostHeader : RequestValidator {
    override fun validate(headers: Headers): Boolean {
        val host = headers["Host"] ?: false
        val origin = headerUrl(headers, "Origin") ?: return false

        return host == origin.host
    }
}

private fun headerUrl(headers: Headers, name: String): URL? {
    return (headers[name] ?: return null).let {
        try {
            URL(it)
        } catch (e: MalformedURLException) {
            return null
        }
    }
}

class HeaderPresent(val name: String) : RequestValidator {
    override fun validate(headers: Headers): Boolean {
        return headers.contains(name)
    }

}

internal class HostTuple(private val scheme: String, private val host: String,
                         private val port: Int? = null) {
    init {
        if (port != null && port < 0) {
            throw IllegalArgumentException("Port must be nonnegative or null")
        }
    }

    fun matches(url: URL): Boolean {
        // if port is unspecified in url, that's exposed as -1, so look for that if port is not set
        val expectedPort = port ?: -1
        return scheme == url.protocol && host == url.host && expectedPort == url.port
    }
}
