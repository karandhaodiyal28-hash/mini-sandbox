using System.Diagnostics;

namespace ZeroTrustSandbox.Services;

/// <summary>
/// Thread-safe sliding-window rate limiter. Used to keep VirusTotal calls
/// within the free tier (4 requests / 60 seconds). Callers <c>await</c>
/// <see cref="WaitAsync"/> which returns once a slot is available.
/// </summary>
public sealed class SlidingWindowRateLimiter
{
    private readonly int _maxRequests;
    private readonly TimeSpan _window;
    private readonly Queue<long> _timestamps = new();
    private readonly SemaphoreSlim _gate = new(1, 1);

    public SlidingWindowRateLimiter(int maxRequests, TimeSpan window)
    {
        if (maxRequests <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxRequests));
        }
        _maxRequests = maxRequests;
        _window = window;
    }

    /// <summary>Number of requests that could be issued right now without waiting.</summary>
    public int AvailableSlots
    {
        get
        {
            _gate.Wait();
            try
            {
                Trim(Stopwatch.GetTimestamp());
                return Math.Max(0, _maxRequests - _timestamps.Count);
            }
            finally
            {
                _gate.Release();
            }
        }
    }

    /// <summary>
    /// Blocks (asynchronously) until a request slot is free, then reserves it.
    /// Honors cancellation while waiting.
    /// </summary>
    public async Task WaitAsync(CancellationToken ct = default)
    {
        while (true)
        {
            TimeSpan delay;
            await _gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var now = Stopwatch.GetTimestamp();
                Trim(now);
                if (_timestamps.Count < _maxRequests)
                {
                    _timestamps.Enqueue(now);
                    return;
                }

                var oldest = _timestamps.Peek();
                var elapsed = Stopwatch.GetElapsedTime(oldest, now);
                delay = _window - elapsed;
                if (delay < TimeSpan.Zero)
                {
                    delay = TimeSpan.Zero;
                }
            }
            finally
            {
                _gate.Release();
            }

            if (delay > TimeSpan.Zero)
            {
                await Task.Delay(delay, ct).ConfigureAwait(false);
            }
        }
    }

    private void Trim(long now)
    {
        while (_timestamps.Count > 0 && Stopwatch.GetElapsedTime(_timestamps.Peek(), now) >= _window)
        {
            _timestamps.Dequeue();
        }
    }
}
