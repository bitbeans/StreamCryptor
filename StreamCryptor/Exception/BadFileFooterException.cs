using System;

public class BadFileFooterException : AggregateException 
{
    public BadFileFooterException()
    {
    }

    public BadFileFooterException(string message)
        : base(message)
    {
    }

    public BadFileFooterException(string message, System.Exception inner)
        : base(message, inner)
    {
    }
}
