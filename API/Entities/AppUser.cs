namespace API.Entities
{
    public class AppUser
    {
        public int Id { get; set; }
        public string UserName { get; set; }
        public byte[] PasswodHash { get; set; }
        public byte[] PasswodSalt { get; set; }
    }
}