package org.mpierce.ktor.csrf

import io.ktor.application.*
import io.ktor.http.Headers
import io.ktor.http.HttpStatusCode
import io.ktor.pipeline.*
import io.ktor.response.respond
import io.ktor.routing.Route
import io.ktor.routing.RouteSelector
import io.ktor.routing.RouteSelectorEvaluation
import io.ktor.routing.RoutingResolveContext
import io.ktor.routing.application
import io.ktor.util.AttributeKey
import java.net.MalformedURLException
import java.net.URL

/**
 * Ktor feature for CSRF protection.
 */
class CsrfProtection(config: Configuration) {
    private val validators = config.validators.toList()
    private val applyToAllRoutes = config.applyToAllRoutes

    class Configuration {
        val validators = mutableListOf<RequestValidator>()

        internal var applyToAllRoutes = false

        fun applyToAllRoutes() {
            applyToAllRoutes = true
        }

        /**
         * Validate the request headers with the provided validator.
         *
         * If called multiple times, all provided validators must pass to approve a request.
         */
        fun validate(rv: RequestValidator) {
            validators.add(rv)
        }
    }

    internal fun interceptPipelineInRoute(pipeline: ApplicationCallPipeline, protected: Boolean) {
        pipeline.insertPhaseAfter(ApplicationCallPipeline.Infrastructure, PhaseInRoute)
        pipeline.intercept(PhaseInRoute) {
            println("interceptPipeline")
            // Should be executed BEFORE the PhaseAfterRoutes, so the attribute is set
            call.attributes.put(AttributeCsrfResult, protected)
        }
    }

    internal fun interceptPipelineAfterRoutes(pipeline: ApplicationCallPipeline) {
        pipeline.insertPhaseAfter(ApplicationCallPipeline.Infrastructure, PhaseAfterRoutes)
        pipeline.intercept(PhaseAfterRoutes) {
            println("interceptPipelineAll")
            val csrfResult = call.attributes.getOrNull(AttributeCsrfResult)
            if ((applyToAllRoutes && csrfResult != false) || csrfResult == true) {
                if (validators.any { !it.validate(call.request.headers) }) {
                    call.response.headers.append("X-CSRF-Rejected", "1")
                    call.respond(HttpStatusCode.BadRequest)
                    finish()
                }
            }
        }
    }

    companion object Feature : ApplicationFeature<ApplicationCallPipeline, Configuration, CsrfProtection> {
        override val key = AttributeKey<CsrfProtection>("CsrfProtection")

        val AttributeCsrfResult = AttributeKey<Boolean>("AttributeCsrfResult")

        private val PhaseInRoute = PipelinePhase("CsrfProtectionInRoute")
        private val PhaseAfterRoutes = PipelinePhase("CsrfProtectionAfterRoutes")

        override fun install(pipeline: ApplicationCallPipeline, configure: Configuration.() -> Unit): CsrfProtection {
            return CsrfProtection(Configuration().apply(configure)).apply {
                interceptPipelineAfterRoutes(pipeline)
            }
        }
    }
}

/**
 * Apply CSRF protection (as configured for the feature) to any child routes.
 *
 * The CsrfProtection feature must already be installed to use this.
 */
fun Route.csrfProtection(build: Route.() -> Unit): Route {
    val protectedRoute = createChild(CsrfRouteSelector())

    application.feature(CsrfProtection).interceptPipelineInRoute(protectedRoute, protected = true)
    protectedRoute.build()
    return protectedRoute
}

fun Route.noCsrfProtection(build: Route.() -> Unit): Route {
    val unprotectedRoute = createChild(CsrfRouteSelector())

    application.feature(CsrfProtection).interceptPipelineInRoute(unprotectedRoute, protected = false)
    unprotectedRoute.build()
    return unprotectedRoute
}

internal class CsrfRouteSelector : RouteSelector(RouteSelectorEvaluation.qualityConstant) {
    override fun evaluate(context: RoutingResolveContext, segmentIndex: Int): RouteSelectorEvaluation {
        return RouteSelectorEvaluation.Constant
    }
}

interface RequestValidator {
    fun validate(headers: Headers): Boolean
}

/**
 * Validates that `Origin` matches a specific host (presumably, the host that this service is deployed at).
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
 * Validates that the `Origin` header matches the host specified in the Host header.
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

/**
 * Require that the given header be present in each request.
 */
class HeaderPresent(private val name: String) : RequestValidator {
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
