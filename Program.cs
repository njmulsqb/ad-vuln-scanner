using System;
using System.DirectoryServices.ActiveDirectory;


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