<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="SiteSetupTool.Default" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head id="Head1" runat="server">
    <title>Script Setup</title>
	<link href="styles/style.css" rel="stylesheet" type="text/css" />

</head>
<body>
    <div class="wrapper">
        <div class="header">    
            <h1>Header Area</h1>
	    </div>
        <form id="containerForm" runat="server">
            <h1>Site Setup</h1>
		    <div class="domain-area">
			    <label>Unique Domain Name:</label>
			    <asp:TextBox ID="DomainName" runat="server" placeholder="example.com.au"></asp:TextBox>
			    <asp:RequiredFieldValidator ID="rfvDomain" runat="server" ErrorMessage="*" ControlToValidate="DomainName" ForeColor="Red"></asp:RequiredFieldValidator>
			    <div class="clearfix"></div>
		    </div>
            <div class="ad-area">
                <label>Please provide your admin username and password to access the AD server:</label>
                <div class="clearfix"></div>
                <label>Domain Username:</label>
                <asp:TextBox ID="loginUserName" runat="server" placeholder="domain\UserName"></asp:TextBox>
                <asp:RequiredFieldValidator ID="UserNameValidator" runat="server" ErrorMessage="*" ControlToValidate="loginUserName" ForeColor="Red" ></asp:RequiredFieldValidator>
                 <asp:RegularExpressionValidator ID="regexpUName" runat="server"     
                                    ErrorMessage="Must be in the Form: DOMAIN\Username." 
                                    ControlToValidate="loginUserName"     
                                    ValidationExpression="^([a-z][a-z0-9.-]+)\\((?! +$)[a-z0-9 ]+)$" />
                <div class="clearfix"></div>
                <label>Domain Password:</label>
                <asp:TextBox ID="loginPassword" runat="server" TextMode="Password"></asp:TextBox>
                <asp:RequiredFieldValidator ID="passwordValidator" runat="server" ErrorMessage="*" ControlToValidate="loginPassword" ForeColor="Red" ></asp:RequiredFieldValidator>
                <div class="clearfix"></div>
			    <label>If this domain already has Active Directory user accounts for IIS and FTP,<br /> do you want to overwrite them?</label>
			    <asp:CheckBox ID="ChkBoxOverwrite" runat="server" />
                <label class="help-text">(Check box for YES, leave blank for NO)</label>
            </div>
		    <div class="server-area">
			    <label>Which server would you like this site to be stored on?</label>
                <asp:TextBox ID="ServerName" runat="server"></asp:TextBox>
		    </div>
            <div class="database-area">
                <label>Do you need a database created?</label>
                <div class="clearfix">
                </div>
			    <asp:CheckBox ID="MySqlChkBox" runat="server"/><asp:Label ID="mySQL" runat="server">MYSQL</asp:Label>
                <div class="clearfix"></div>
                <asp:CheckBox ID="SqlChkBox" runat="server"/><asp:Label ID="msSQL" runat="server">MS SQL</asp:Label>
                <div class="clearfix"></div>
                <asp:Button ID="BtnExecuteScript" runat="server" Text="Run Scripts" OnClick="BtnExecuteScript_Click" />
            </div>
         
          
		    <div class="output-area">
			    Script output:
			    <asp:TextBox ID="TxtOutput" runat="server" TextMode="MultiLine" ReadOnly="true"></asp:TextBox>
			    <asp:Button ID="BtnClear" runat="server" Text="Clear All Values and Output" OnClick="BtnClear_Click" CausesValidation="False"/>
                
                <asp:Button ID="BtnEmailResults" runat="server" Text="Email Results" OnClick="emailResults" />
		    </div>
        </form>
        <div class="footer">
            <h4>Footer text</h4>
        </div>
    </div>
</body>
</html>
