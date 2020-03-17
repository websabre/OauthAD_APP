using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Web;
using System.Web.Script.Serialization;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace OauthFrontEnd
{
    public partial class Login : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {

        }

        protected void btnLogin_Click(object sender, EventArgs e)
        {
            string apiUrl = "http://localhost:3097/api/WebApi/";
            bool isLdap = false;
            //var input = new
            //{
            //    grant_type="password",
            //    username = txtUserName.Text.Trim(),
            //    password=txtPassword.Text.Trim(),
            //    IsLdap=false
            //};

            if(ddlAD.SelectedValue=="Yes")
            {
                isLdap = true;
            }
            var client = new RestClient("http://localhost:3097/token");
            var request = new RestRequest(Method.POST);
            request.AddHeader("content-type", "application/x-www-form-urlencoded");
            request.AddParameter("application/x-www-form-urlencoded", "grant_type=password&username="+txtUserName.Text.Trim()+"&password="+ txtPassword.Text.Trim()+" &IsLdap="+isLdap+"", ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);
            var result = response.Content;
            var words = result.Split(',');

            var key = words[0].Split(':')[1].Replace("\"", "");
            var token=key.Replace("\"", "");
            AuthToken(key);

            //string inputJson = (new JavaScriptSerializer()).Serialize(input);
            //HttpClient client = new HttpClient();
            //HttpContent inputContent = new StringContent(inputJson, Encoding.UTF8, "application/x-www-form-urlencoded");
            //HttpResponseMessage response = client.PostAsync(apiUrl, inputContent).Result;
        }
        void AuthToken(string token)
        {

            var client = new RestClient("http://localhost:3097/api/WebApi/");
            var request = new RestRequest(Method.GET);
            request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
            request.AddHeader("Authorization", "Bearer "+ token);
            IRestResponse response = client.Execute(request);
            var result = response.Content;

            lblResponce.Text = result.ToString();


        }

    }
}