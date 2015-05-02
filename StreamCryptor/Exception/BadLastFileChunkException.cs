using System;

public class BadLastFileChunkException : Exception
{
    public BadLastFileChunkException()
    {
    }

    public BadLastFileChunkException(string message)
        : base(message)
    {
    }

    public BadLastFileChunkException(string message, System.Exception inner)
        : base(message, inner)
    {
    }
}
