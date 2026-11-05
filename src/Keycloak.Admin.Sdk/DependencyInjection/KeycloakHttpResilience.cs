using Microsoft.Extensions.Http.Resilience;
using Polly;

namespace Keycloak.Admin.Sdk;

internal static class KeycloakHttpResilience
{
    internal static ResilienceHandler CreateHandler(KeycloakHttpResilienceOptions options, TimeProvider clock)
    {
        if (!options.Enabled) return new ResilienceHandler(ResiliencePipeline<HttpResponseMessage>.Empty);
        var builder = new ResiliencePipelineBuilder<HttpResponseMessage> { TimeProvider = clock };
        builder.AddTimeout(options.TotalRequestTimeout);
        if (options.MaxRetryAttempts > 0)
            builder.AddRetry(new HttpRetryStrategyOptions
            {
                MaxRetryAttempts = options.MaxRetryAttempts,
                Delay = options.RetryDelay,
                UseJitter = options.UseJitter
            });
        if (options.EnableCircuitBreaker)
            builder.AddCircuitBreaker(new HttpCircuitBreakerStrategyOptions
            {
                FailureRatio = options.CircuitBreakerFailureRatio,
                MinimumThroughput = options.CircuitBreakerMinimumThroughput,
                SamplingDuration = options.CircuitBreakerSamplingDuration,
                BreakDuration = options.CircuitBreakerBreakDuration
            });
        builder.AddTimeout(options.AttemptTimeout);
        var pipeline = builder.Build();
        // Bypass the WHOLE pipeline for writes, token POST and one-shot content, even while the read circuit is open.
        return new ResilienceHandler(request => request.Content is null && (request.Method == HttpMethod.Get || request.Method == HttpMethod.Head)
            ? pipeline : ResiliencePipeline<HttpResponseMessage>.Empty);
    }
}
