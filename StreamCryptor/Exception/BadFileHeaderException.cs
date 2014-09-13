using System;

public class BadFileHeaderException : System.Exception
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
