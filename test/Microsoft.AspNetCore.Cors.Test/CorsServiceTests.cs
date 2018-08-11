// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Testing;
using Xunit;

namespace Microsoft.AspNetCore.Cors.Infrastructure
{
    public class CorsServiceTests
    {
        [Fact]
        public void EvaluatePolicy_NoOrigin_ReturnsInvalidResult()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext("GET", origin: null);

            // Act
            var result = corsService.EvaluatePolicy(requestContext, new CorsPolicy());

            // Assert
            Assert.Null(result.AllowedOrigin);
            Assert.False(result.VaryByOrigin);
        }

        [Fact]
        public void EvaluatePolicy_NoMatchingOrigin_ReturnsInvalidResult()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(origin: "http://example.com");
            var policy = new CorsPolicy();
            policy.Origins.Add("bar");

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.False(result.IsCorsResponseAllowed);
        }

        [Fact]
        public void EvaluatePolicy_EmptyOriginsPolicy_ReturnsInvalidResult()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(origin: "http://example.com");
            var policy = new CorsPolicy();

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.False(result.IsCorsResponseAllowed);
        }

        [Fact]
        public void EvaluatePolicy_IsOriginAllowedReturnsFalse_ReturnsInvalidResult()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(origin: "http://example.com");
            var policy = new CorsPolicy()
            {
                IsOriginAllowed = origin => false
            };
            policy.Origins.Add("example.com");

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.False(result.IsCorsResponseAllowed);
        }

        [Fact]
        public void EvaluatePolicy_AllowAnyOrigin_DoesNotSupportCredentials_EmitsOriginHeader()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(origin: "http://example.com");

            var policy = new CorsPolicy
            {
                SupportsCredentials = false
            };

            policy.Origins.Add(CorsConstants.AnyOrigin);

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.Equal("http://example.com", result.AllowedOrigin);
        }

        [Fact]
        public void EvaluatePolicy_AllowAnyOrigin_SupportsCredentials_AddsSpecificOrigin()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(origin: "http://example.com");
            var policy = new CorsPolicy
            {
                SupportsCredentials = true
            };
            policy.Origins.Add(CorsConstants.AnyOrigin);

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.Equal("http://example.com", result.AllowedOrigin);
            Assert.True(result.VaryByOrigin);
        }

        [Fact]
        public void EvaluatePolicy_DoesNotSupportCredentials_AllowCredentialsReturnsFalse()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(origin: "http://example.com");
            var policy = new CorsPolicy
            {
                SupportsCredentials = false
            };
            policy.Origins.Add(CorsConstants.AnyOrigin);

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.False(result.SupportsCredentials);
        }

        [Fact]
        public void EvaluatePolicy_SupportsCredentials_AllowCredentialsReturnsTrue()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(origin: "http://example.com");
            var policy = new CorsPolicy
            {
                SupportsCredentials = true
            };
            policy.Origins.Add(CorsConstants.AnyOrigin);

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.True(result.SupportsCredentials);
        }

        [Fact]
        public void EvaluatePolicy_NoExposedHeaders_NoAllowExposedHeaders()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(origin: "http://example.com");
            var policy = new CorsPolicy();
            policy.Origins.Add(CorsConstants.AnyOrigin);

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.Empty(result.AccessControlExposeHeaders);
        }

        [Fact]
        public void EvaluatePolicy_OneExposedHeaders_HeadersAllowed()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(origin: "http://example.com");
            var policy = new CorsPolicy();
            policy.Origins.Add(CorsConstants.AnyOrigin);
            policy.ExposedHeaders.Add("foo");

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.Equal("foo", result.AccessControlExposeHeaders);
        }

        [Fact]
        public void EvaluatePolicy_ManyExposedHeaders_HeadersAllowed()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(origin: "http://example.com");
            var policy = new CorsPolicy();
            policy.Origins.Add(CorsConstants.AnyOrigin);
            policy.ExposedHeaders.Add("foo");
            policy.ExposedHeaders.Add("bar");
            policy.ExposedHeaders.Add("baz");

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.Equal("foo,bar,baz", result.AccessControlExposeHeaders);
        }

        [Fact]
        public void EvaluatePolicy_PreflightRequest_MethodNotAllowed()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(method: "OPTIONS", origin: "http://example.com", accessControlRequestMethod: "PUT");
            var policy = new CorsPolicy();
            policy.Origins.Add(CorsConstants.AnyOrigin);
            policy.Methods.Add("GET");

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.Equal("GET", result.AccessControlAllowMethods);
        }

        [Fact]
        public void EvaluatePolicy_PreflightRequest_MethodAllowed_ReturnsAllowMethods()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(method: "OPTIONS", origin: "http://example.com", accessControlRequestMethod: "PUT");
            var policy = new CorsPolicy();
            policy.Origins.Add(CorsConstants.AnyOrigin);
            policy.Methods.Add("PUT");

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.NotNull(result);
            Assert.Equal("PUT", result.AccessControlAllowMethods);
        }

        [Theory]
        [InlineData("OpTions")]
        [InlineData("OPTIONS")]
        public void EvaluatePolicy_CaseInsensitivePreflightRequest_OriginAllowed_ReturnsOrigin(string preflightMethod)
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(
                method: preflightMethod,
                origin: "http://example.com",
                accessControlRequestMethod: "PUT");
            var policy = new CorsPolicy();
            policy.Origins.Add(CorsConstants.AnyOrigin);
            policy.Origins.Add("http://example.com");
            policy.Methods.Add("*");

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.Equal("http://example.com", result.AllowedOrigin);
        }

        [Fact]
        public void EvaluatePolicy_PreflightRequest_IsOriginAllowedReturnsTrue_ReturnsOrigin()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(
                method: "OPTIONS",
                origin: "http://example.com",
                accessControlRequestMethod: "PUT");
            var policy = new CorsPolicy
            {
                IsOriginAllowed = origin => true
            };
            policy.Methods.Add("*");

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.Equal("http://example.com", result.AllowedOrigin);
        }

        [Fact]
        public void EvaluatePolicy_PreflightRequest_SupportsCredentials_AllowCredentialsReturnsTrue()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(method: "OPTIONS", origin: "http://example.com", accessControlRequestMethod: "PUT");
            var policy = new CorsPolicy
            {
                SupportsCredentials = true
            };
            policy.Origins.Add(CorsConstants.AnyOrigin);
            policy.Methods.Add("*");

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.True(result.SupportsCredentials);
        }

        [Fact]
        public void EvaluatePolicy_PreflightRequest_NoPreflightMaxAge_NoPreflightMaxAgeSet()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(method: "OPTIONS", origin: "http://example.com", accessControlRequestMethod: "PUT");
            var policy = new CorsPolicy
            {
                PreflightMaxAge = null
            };
            policy.Origins.Add(CorsConstants.AnyOrigin);
            policy.Methods.Add("*");

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.Null(result.AccessControlMaxAge);
        }

        [Fact]
        public void EvaluatePolicy_PreflightRequest_PreflightMaxAge_PreflightMaxAgeSet()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(method: "OPTIONS", origin: "http://example.com", accessControlRequestMethod: "PUT");
            var policy = new CorsPolicy
            {
                PreflightMaxAge = TimeSpan.FromSeconds(10)
            };
            policy.Origins.Add(CorsConstants.AnyOrigin);
            policy.Methods.Add("*");

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.Equal("10", result.AccessControlMaxAge);
        }

        [Fact]
        public void EvaluatePolicy_PreflightRequest_AnyMethod_ReturnsRequestMethod()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(method: "OPTIONS", origin: "http://example.com", accessControlRequestMethod: "GET");
            var policy = new CorsPolicy();
            policy.Origins.Add(CorsConstants.AnyOrigin);
            policy.Methods.Add("*");

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.Equal("*", result.AccessControlAllowMethods);
        }

        [Theory]
        [InlineData("Put")]
        [InlineData("PUT")]
        public void EvaluatePolicy_CaseInsensitivePreflightRequest_ReturnsAllowedMethods(string method)
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(
                method: "OPTIONS",
                origin: "http://example.com",
                accessControlRequestMethod: method);
            var policy = new CorsPolicy();
            policy.Origins.Add(CorsConstants.AnyOrigin);
            policy.Methods.Add("PUT");
            policy.Methods.Add("DELETE");

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.Equal("PUT,DELETE", result.AccessControlAllowMethods);
        }

        [Fact]
        public void EvaluatePolicy_PreflightRequest_NoHeadersRequested_AllowedAllHeaders()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(method: "OPTIONS", origin: "http://example.com", accessControlRequestMethod: "PUT");
            var policy = new CorsPolicy();
            policy.Origins.Add(CorsConstants.AnyOrigin);
            policy.Methods.Add("*");
            policy.Headers.Add("*");

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.Equal("*", result.AccessControlAllowHeaders);
            Assert.Equal("*", result.AccessControlAllowMethods);
        }

        [Fact]
        public void EvaluatePolicy_PreflightRequest_WithCredentials_AllowAllHeaders_ReturnsRequestedHeaders()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(
                method: "OPTIONS",
                origin: "http://example.com",
                accessControlRequestMethod: "PUT",
                accessControlRequestHeaders: new[] { "foo", "bar" });
            var policy = new CorsPolicy();
            policy.Origins.Add(CorsConstants.AnyOrigin);
            policy.Methods.Add("*");
            policy.Headers.Add("*");
            policy.SupportsCredentials = true;

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.Equal("foo,bar", result.AccessControlAllowHeaders);
            Assert.Equal("PUT", result.AccessControlAllowMethods);
        }
        
        [Fact]
        public void EvaluatePolicy_PreflightRequest_HeadersRequested_NotAllHeaderMatches_ReturnsInvalidResult()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(
                method: "OPTIONS",
                origin: "http://example.com",
                accessControlRequestMethod: "PUT",
                accessControlRequestHeaders: new[] { "match", "noMatch" });
            var policy = new CorsPolicy();
            policy.Origins.Add(CorsConstants.AnyOrigin);
            policy.Methods.Add("*");
            policy.Headers.Add("match");
            policy.Headers.Add("foo");

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.Equal("match,foo", result.AccessControlAllowHeaders);
            Assert.Equal("*", result.AccessControlAllowMethods);
        }

        [Fact]
        public void ApplyResult_ReturnsNoHeaders_ByDefault()
        {
            // Arrange
            var result = new CorsResult();
            var httpContext = new DefaultHttpContext();
            var service = new CorsService(new TestCorsOptions());

            // Act
            service.ApplyResult(result, httpContext.Response);

            // Assert
            Assert.Empty(httpContext.Response.Headers);
        }

        [Fact]
        public void ApplyResult_AllowOrigin_AllowOriginHeaderAdded()
        {
            // Arrange
            var result = new CorsResult
            {
                IsCorsResponseAllowed = true,
                AllowedOrigin = "http://example.com"
            };

            var httpContext = new DefaultHttpContext();
            var service = new CorsService(new TestCorsOptions());

            // Act
            service.ApplyResult(result, httpContext.Response);

            // Assert
            Assert.Equal("http://example.com", httpContext.Response.Headers["Access-Control-Allow-Origin"]);
        }

        [Fact]
        public void ApplyResult_NoAllowOrigin_AllowOriginHeaderNotAdded()
        {
            // Arrange
            var result = new CorsResult
            {
                IsCorsResponseAllowed = true,
                AllowedOrigin = null
            };

            var httpContext = new DefaultHttpContext();
            var service = new CorsService(new TestCorsOptions());

            // Act
            service.ApplyResult(result, httpContext.Response);

            // Assert
            Assert.DoesNotContain("Access-Control-Allow-Origin", httpContext.Response.Headers.Keys);
        }

        [Fact]
        public void ApplyResult_AllowCredentials_AllowCredentialsHeaderAdded()
        {
            // Arrange
            var result = new CorsResult
            {
                IsCorsResponseAllowed = true,
                SupportsCredentials = true
            };

            var service = new CorsService(new TestCorsOptions());

            // Act
            var httpContext = new DefaultHttpContext();
            service.ApplyResult(result, httpContext.Response);

            // Assert
            Assert.Equal("true", httpContext.Response.Headers["Access-Control-Allow-Credentials"]);
        }

        [Fact]
        public void ApplyResult_AddVaryHeader_VaryHeaderAdded()
        {
            // Arrange
            var result = new CorsResult
            {
                IsCorsResponseAllowed = true,
                VaryByOrigin = true
            };

            var httpContext = new DefaultHttpContext();
            var service = new CorsService(new TestCorsOptions());

            // Act
            service.ApplyResult(result, httpContext.Response);

            // Assert
            Assert.Equal("Origin", httpContext.Response.Headers["Vary"]);
        }

        [Fact]
        public void ApplyResult_NoAllowCredentials_AllowCredentialsHeaderNotAdded()
        {
            // Arrange
            var result = new CorsResult
            {
                IsCorsResponseAllowed = true,
                SupportsCredentials = false
            };

            var httpContext = new DefaultHttpContext();
            var service = new CorsService(new TestCorsOptions());

            // Act
            service.ApplyResult(result, httpContext.Response);

            // Assert
            Assert.DoesNotContain("Access-Control-Allow-Credentials", httpContext.Response.Headers.Keys);
        }

        [Fact]
        public void ApplyResult_NoAllowMethods_AllowMethodsHeaderNotAdded()
        {
            // Arrange
            var result = new CorsResult
            {
                IsCorsResponseAllowed = true,
                // AllowMethods is empty by default
            };

            var httpContext = new DefaultHttpContext();
            var service = new CorsService(new TestCorsOptions());

            // Act
            service.ApplyResult(result, httpContext.Response);

            // Assert
            Assert.DoesNotContain("Access-Control-Allow-Methods", httpContext.Response.Headers.Keys);
        }

        [Fact]
        public void ApplyResult_OneAllowMethods_AllowMethodsHeaderAdded()
        {
            // Arrange
            var result = new CorsResult
            {
                IsCorsResponseAllowed = true,
                IsPreflightRequest = true,
                AccessControlAllowMethods = "PUT"
            };

            var httpContext = new DefaultHttpContext();
            var service = new CorsService(new TestCorsOptions());

            // Act
            service.ApplyResult(result, httpContext.Response);

            // Assert
            Assert.Equal("PUT", httpContext.Response.Headers["Access-Control-Allow-Methods"]);
        }

        [Fact]
        public void ApplyResult_NoAllowHeaders_AllowHeadersHeaderNotAdded()
        {
            // Arrange
            var result = new CorsResult
            {
                // AllowHeaders is empty by default
                IsCorsResponseAllowed = true,
            };

            var httpContext = new DefaultHttpContext();
            var service = new CorsService(new TestCorsOptions());

            // Act
            service.ApplyResult(result, httpContext.Response);

            // Assert
            Assert.DoesNotContain("Access-Control-Allow-Headers", httpContext.Response.Headers.Keys);
        }

        [Fact]
        public void ApplyResult_OneAllowHeaders_AllowHeadersHeaderAdded()
        {
            // Arrange
            var result = new CorsResult
            {
                IsCorsResponseAllowed = true,
                IsPreflightRequest = true,
                AccessControlAllowHeaders = "foo"
            };

            var httpContext = new DefaultHttpContext();
            var service = new CorsService(new TestCorsOptions());

            // Act
            service.ApplyResult(result, httpContext.Response);

            // Assert
            Assert.Equal("foo", httpContext.Response.Headers["Access-Control-Allow-Headers"]);
        }


        [Fact]
        public void ApplyResult_NoAllowExposedHeaders_ExposedHeadersHeaderNotAdded()
        {
            // Arrange
            var result = new CorsResult
            {
                // AllowExposedHeaders is empty by default
                IsCorsResponseAllowed = true,
            };

            var httpContext = new DefaultHttpContext();
            var service = new CorsService(new TestCorsOptions());

            // Act
            service.ApplyResult(result, httpContext.Response);

            // Assert
            Assert.DoesNotContain("Access-Control-Expose-Headers", httpContext.Response.Headers.Keys);
        }

        [Fact]
        public void ApplyResult_OneAllowExposedHeaders_ExposedHeadersHeaderAdded()
        {
            // Arrange
            var result = new CorsResult
            {
                IsCorsResponseAllowed = true,
                AccessControlExposeHeaders = "foo",
            };

            var httpContext = new DefaultHttpContext();
            var service = new CorsService(new TestCorsOptions());

            // Act
            service.ApplyResult(result, httpContext.Response);

            // Assert
            Assert.Equal("foo", httpContext.Response.Headers["Access-Control-Expose-Headers"]);
        }

        [Fact]
        public void EvaluatePolicy_MultiOriginsPolicy_ReturnsVaryByOriginHeader()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(origin: "http://example.com");
            var policy = new CorsPolicy();
            policy.Origins.Add("http://example.com");
            policy.Origins.Add("http://example-two.com");

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.NotNull(result.AllowedOrigin);
            Assert.True(result.VaryByOrigin);
        }

        [Fact]
        public void EvaluatePolicy_MultiOriginsPolicy_NoMatchingOrigin_ReturnsInvalidResult()
        {
            // Arrange
            var corsService = new CorsService(new TestCorsOptions());
            var requestContext = GetHttpContext(origin: "http://example.com");
            var policy = new CorsPolicy();
            policy.Origins.Add("http://example-two.com");
            policy.Origins.Add("http://example-three.com");

            // Act
            var result = corsService.EvaluatePolicy(requestContext, policy);

            // Assert
            Assert.False(result.IsCorsResponseAllowed);
        }

        private static HttpContext GetHttpContext(
            string method = null,
            string origin = null,
            string accessControlRequestMethod = null,
            string[] accessControlRequestHeaders = null)
        {
            var context = new DefaultHttpContext();

            if (method != null)
            {
                context.Request.Method = method;
            }

            if (origin != null)
            {
                context.Request.Headers.Add(CorsConstants.Origin, new[] { origin });
            }

            if (accessControlRequestMethod != null)
            {
                context.Request.Headers.Add(CorsConstants.AccessControlRequestMethod, new[] { accessControlRequestMethod });
            }

            if (accessControlRequestHeaders != null)
            {
                context.Request.Headers.Add(CorsConstants.AccessControlRequestHeaders, accessControlRequestHeaders);
            }

            return context;
        }
    }
}
