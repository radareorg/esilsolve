int check(int x)
{
    if((0xcafe^x)%17492 == 5203)
    {
        if((0xbabe^x)%17492 == 8127)
        {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char **argv) 
{
    return check(atoi(argv[1]));
}