using System;

public class BadFileChunkException : Exception
{
    public BadFileChunkException()
    {
    }

    public BadFileChunkException(string message)
        : base(message)
    {
    }

    public BadFileChunkException(string message, Exception inner)
        : base(message, inner)
    {
    }
}