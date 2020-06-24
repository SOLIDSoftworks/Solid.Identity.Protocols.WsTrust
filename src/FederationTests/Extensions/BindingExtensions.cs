//using Solid.Http;
//using Solid.Testing.AspNetCore.Extensions.XUnit;
//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Text;
//using System.Threading.Tasks;
//using System.Xml;

//namespace System.ServiceModel.Channels
//{
//    public static class BindingExtensions
//    {
//        public static Binding WithoutTransportSecurity(this Binding binding)
//        {
//            var custom = binding as CustomBinding;
//            if (custom == null)
//                custom = new CustomBinding(binding);

//            var security = custom.Elements.OfType<SecurityBindingElement>();
//            foreach (var element in security)
//                element.AllowInsecureTransport = true;

//            var https = custom
//                .Elements
//                .OfType<HttpTransportBindingElement>()
//                .Where(e => e.Scheme == "https")
//                .FirstOrDefault();
//            if (https != null)
//            {
//                var http = new HttpTransportBindingElement();
//                custom.Elements.Remove(https);
//                custom.Elements.Add(http);
//            }
//            return custom;
//        }
//    }
//}
