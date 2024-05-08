// See https://aka.ms/new-console-template for more information
using System;
using System.DirectoryServices.ActiveDirectory;


Console.WriteLine("Hello, World!");

bool isDomainJoined = IsComputerJoinedToDomain();

if (isDomainJoined)
{
    Console.WriteLine("The computer is joined to a domain.");
}
else
{
    Console.WriteLine("The computer is not joined to a domain.");
}


static bool IsComputerJoinedToDomain()
    {
        try
        {
            Domain.GetComputerDomain(); // This method will throw an exception if not joined to a domain
            return true;
        }
        catch (ActiveDirectoryObjectNotFoundException)
        {
            return false;
        }
    }