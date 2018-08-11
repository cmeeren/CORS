// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Microsoft.AspNetCore.Cors.Internal;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace Microsoft.AspNetCore.Cors.Infrastructure
{
    /// <summary>
    /// Default implementation of <see cref="ICorsService"/>.
    /// </summary>
    public class CorsService : ICorsService
    {
        private static readonly CorsResult FailedResult = new CorsResult();

        private readonly CorsOptions _options;
        private readonly ILogger _logger;

        /// <summary>
        /// Creates a new instance of the <see cref="CorsService"/>.
        /// </summary>
        /// <param name="options">The option model representing <see cref="CorsOptions"/>.</param>
        public CorsService(IOptions<CorsOptions> options)
            : this(options, loggerFactory: NullLoggerFactory.Instance)
        {
        }

        /// <summary>
        /// Creates a new instance of the <see cref="CorsService"/>.
        /// </summary>
        /// <param name="options">The option model representing <see cref="CorsOptions"/>.</param>
        /// <param name="loggerFactory">The <see cref="ILoggerFactory"/>.</param>
        public CorsService(IOptions<CorsOptions> options, ILoggerFactory loggerFactory)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            _options = options.Value;
            _logger = loggerFactory?.CreateLogger<CorsService>();
        }

        /// <summary>
        /// Looks up a policy using the <paramref name="policyName"/> and then evaluates the policy using the passed in
        /// <paramref name="context"/>.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="policyName"></param>
        /// <returns>A <see cref="CorsResult"/> which contains the result of policy evaluation and can be
        /// used by the caller to set appropriate response headers.</returns>
        public CorsResult EvaluatePolicy(HttpContext context, string policyName)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var policy = _options.GetPolicy(policyName);
            return EvaluatePolicy(context, policy);
        }

        /// <inheritdoc />
        public CorsResult EvaluatePolicy(HttpContext context, CorsPolicy policy)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            var origin = context.Request.Headers[CorsConstants.Origin];
            // A CORS-preflight request ... uses `OPTIONS` as method and includes these headers:
            // Access-Control-Request-Method, Access-Control-Request-Headers
            // To support legacy behavior, we'll ignore the presence of Access-Control-Request-Headers header. 
            var requestHeaders = context.Request.Headers;
            var isPreflightRequest =
                string.Equals(context.Request.Method, CorsConstants.PreflightHttpMethod, StringComparison.OrdinalIgnoreCase) &&
                requestHeaders.ContainsKey(CorsConstants.AccessControlRequestMethod);

            var corsResult = new CorsResult
            {
                IsPreflightRequest = isPreflightRequest,
                IsCorsResponseAllowed = IsOriginAllowed(policy, origin),
            };

            if (isPreflightRequest)
            {
                EvaluatePreflightRequest(context, policy, corsResult);
            }
            else
            {
                EvaluateRequest(context, policy, corsResult);
            }

            _logger?.PolicySuccess();
            return corsResult;
        }

        public virtual void EvaluateRequest(HttpContext context, CorsPolicy policy, CorsResult result)
        {
            CalculateResult(context, policy, result);
        }

        public virtual void EvaluatePreflightRequest(HttpContext context, CorsPolicy policy, CorsResult result)
        {
            CalculateResult(context, policy, result);
        }

        /// <inheritdoc />
        public virtual void ApplyResult(CorsResult result, HttpResponse response)
        {
            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response));
            }

            if (!result.IsCorsResponseAllowed)
            {
                // In case a server does not wish to participate in the CORS protocol, its HTTP response to the CORS or CORS-preflight request must not include any of the above headers. 
                return;
            }

            WriteHeader(CorsConstants.AccessControlAllowOrigin, result.AllowedOrigin);

            if (result.SupportsCredentials)
            {
                response.Headers[CorsConstants.AccessControlAllowCredentials] = "true";
            }

            if (result.IsPreflightRequest)
            {
                _logger?.IsPreflightRequest();
                // An HTTP response to a CORS-preflight request can include the following headers:
                // `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, `Access-Control-Max-Age`
                WriteHeader(CorsConstants.AccessControlAllowHeaders, result.AccessControlAllowHeaders);
                WriteHeader(CorsConstants.AccessControlAllowMethods, result.AccessControlAllowMethods);
                WriteHeader(CorsConstants.AccessControlMaxAge, result.AccessControlMaxAge);
            }
            else
            {
                // An HTTP response to a CORS request that is not a CORS-preflight request can also include the following header:
                // `Access-Control-Expose-Headers`
                WriteHeader(CorsConstants.AccessControlExposeHeaders, result.AccessControlExposeHeaders);
            }

            if (result.VaryByOrigin)
            {
                response.Headers["Vary"] = "Origin";
            }

            void WriteHeader(string headerName, string headerValue)
            {
                if (!string.IsNullOrEmpty(headerValue))
                {
                    response.Headers[headerName] = headerValue;
                }
            }
        }

        private static void CalculateResult(HttpContext context, CorsPolicy policy, CorsResult result)
        {
            var origin = context.Request.Headers[CorsConstants.Origin];

            // Indicates whether the response can be shared, via returning the literal value of the `Origin` request header
            result.AllowedOrigin = origin;
            result.SupportsCredentials = policy.SupportsCredentials;

            // Cache header values
            if (!policy.HeadersCached)
            {
                policy.AccessControlAllowHeaders = GetHeaderValue(policy.Headers);
                policy.AccessControlAllowMethods = GetHeaderValue(policy.Methods);
                policy.AccessControlExposeHeaders = GetHeaderValue(policy.ExposedHeaders);
                policy.AccessControlMaxAge = policy.PreflightMaxAge?.TotalSeconds.ToString(CultureInfo.InvariantCulture);
                policy.HeadersCached = true;
            }

            if (policy.SupportsCredentials)
            {
                // When Access-Control-Allow-Credentials is true, Access-Control headers cannot include '*'. We'll respond
                // with the requested headers if available.
                result.AccessControlAllowMethods = ((string)context.Request.Headers[CorsConstants.AccessControlRequestMethod])
                    ?? policy.AccessControlAllowMethods;

                result.AccessControlAllowHeaders = ((string)context.Request.Headers[CorsConstants.AccessControlRequestHeaders])
                    ?? policy.AccessControlAllowHeaders;
            }
            else
            {
                result.AccessControlAllowMethods = policy.AccessControlAllowMethods;
                result.AccessControlAllowHeaders = policy.AccessControlAllowHeaders;
            }

            result.VaryByOrigin = policy.AddVaryByOriginHeader(origin);
            result.AccessControlExposeHeaders = policy.AccessControlExposeHeaders;
            result.AccessControlMaxAge = policy.AccessControlMaxAge;
        }


        private bool IsOriginAllowed(CorsPolicy policy, StringValues origin)
        {
            if (StringValues.IsNullOrEmpty(origin))
            {
                _logger?.RequestDoesNotHaveOriginHeader();
                return false;
            }

            _logger?.RequestHasOriginHeader(origin);
            if (policy.AllowAnyOrigin || policy.IsOriginAllowed(origin))
            {
                return true;
            }
            _logger?.PolicyFailure();
            _logger?.OriginNotAllowed(origin);
            return false;
        }

        private static string GetHeaderValue(IList<string> headerValues)
        {
            if (headerValues.Count == 0)
            {
                return string.Empty;
            }
            else if (headerValues.Count == 1)
            {
                return headerValues[0];
            }

            return string.Join(",", headerValues.Select(QuoteIfNeeded));

            string QuoteIfNeeded(string value)
            {
                if (!string.IsNullOrEmpty(value) &&
                    value.Contains(',') &&
                    (value[0] != '"' || value[value.Length - 1] != '"'))
                {
                    return $"\"{value}\"";
                }
                return value;
            }
        }
    }
}
