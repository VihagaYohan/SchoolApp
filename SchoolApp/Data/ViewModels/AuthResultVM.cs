using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SchoolApp.Data.ViewModels
{
	public class AuthResultVM
	{
		public string Token { get; set; }
		public DateTime ExpireAt { get; set; }
	}
}
