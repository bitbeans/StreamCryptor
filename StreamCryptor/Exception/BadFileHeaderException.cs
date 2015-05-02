using System;

public class BadFileHeaderException : Exception
{
    public BadFileHeaderException()
    {
    }

    public BadFileHeaderException(string message)
        : base(message)
    {
    }

    public BadFileHeaderException(string message, System.Exception inner)
        : base(message, inner)
    {
    }
}
