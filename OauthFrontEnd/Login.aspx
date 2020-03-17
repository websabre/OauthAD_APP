<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Login.aspx.cs" Inherits="OauthFrontEnd.Login" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
</head>
<body>
    <form id="form1" runat="server">
        <div>
            <asp:Label ID="lblUserName" runat="server" Text="User Name"></asp:Label>
            <br />
            <asp:TextBox ID="txtUserName" runat="server"></asp:TextBox>
            <br />
            <br />
            <asp:Label ID="lblPassword" runat="server" Text="Password"></asp:Label>
                <br />
            <asp:TextBox ID="txtPassword" runat="server"></asp:TextBox>
            <br />
              <br />
            <asp:Label ID="lblAD" runat="server" Text="AD Configured?"></asp:Label>
                <br />
            <asp:DropDownList ID="ddlAD" runat="server">
                <asp:ListItem>Yes</asp:ListItem>
                <asp:ListItem>No</asp:ListItem>
            </asp:DropDownList>
            <br/>
              <br />
            <asp:Button ID="btnLogin" runat="server" Text="Login" OnClick="btnLogin_Click" />
            
            <br />
            <br />
            <asp:Label ID="lblResponce" runat="server" Text=""></asp:Label>
        </div>
    </form>
</body>
</html>
