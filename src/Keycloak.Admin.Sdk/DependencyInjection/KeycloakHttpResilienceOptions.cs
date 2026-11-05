namespace Keycloak.Admin.Sdk;

/// <summary>Immutable settings for a named client's read-only resilience pipeline. No hedging or body logging is installed.</summary>
public sealed class KeycloakHttpResilienceOptions
{
    public bool Enabled { get; init; }
    /// <summary>Additional attempts per HTTP send, from zero to ten. Zero disables transient retries.</summary>
    public int MaxRetryAttempts { get; init; } = 2;
    /// <summary>Initial exponential backoff, from zero to one minute. Retry-After is respected within the total timeout.</summary>
    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromMilliseconds(200);
    public bool UseJitter { get; init; } = true;
    /// <summary>One HTTP send including transient retries; excludes token acquisition, SDK 401 recovery and response body reading.</summary>
    public TimeSpan TotalRequestTimeout { get; init; } = TimeSpan.FromSeconds(30);
    public TimeSpan AttemptTimeout { get; init; } = TimeSpan.FromSeconds(10);
    public bool EnableCircuitBreaker { get; init; } = true;
    public double CircuitBreakerFailureRatio { get; init; } = 0.5;
    public int CircuitBreakerMinimumThroughput { get; init; } = 20;
    public TimeSpan CircuitBreakerSamplingDuration { get; init; } = TimeSpan.FromSeconds(30);
    public TimeSpan CircuitBreakerBreakDuration { get; init; } = TimeSpan.FromSeconds(5);

    internal static bool IsValid(KeycloakHttpResilienceOptions? value) => value is not null
        && value.MaxRetryAttempts is >= 0 and <= 10
        && value.RetryDelay >= TimeSpan.Zero && value.RetryDelay <= TimeSpan.FromMinutes(1)
        && value.AttemptTimeout >= TimeSpan.FromMilliseconds(1) && value.AttemptTimeout <= value.TotalRequestTimeout
        && value.TotalRequestTimeout <= TimeSpan.FromDays(1)
        && value.CircuitBreakerFailureRatio > 0 && value.CircuitBreakerFailureRatio <= 1
        && value.CircuitBreakerMinimumThroughput >= 2
        && value.CircuitBreakerSamplingDuration >= TimeSpan.FromMilliseconds(500) && value.CircuitBreakerSamplingDuration <= TimeSpan.FromDays(1)
        && value.CircuitBreakerBreakDuration >= TimeSpan.FromMilliseconds(500) && value.CircuitBreakerBreakDuration <= TimeSpan.FromDays(1);
}
