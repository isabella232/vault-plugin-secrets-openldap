package openldap

import (
	"context"
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	"github.com/hashicorp/vault-plugin-secrets-openldap/template"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryboe/q"
)

func (b *backend) pathDynamicCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	dRole, err := retrieveDynamicRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve dynamic role: %w", err)
	}
	if dRole == nil {
		return nil, nil
	}

	config, err := readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, fmt.Errorf("missing OpenLDAP configuration")
	}

	username, err := generateUsername(req, dRole)
	if err != nil {
		return nil, fmt.Errorf("failed to generate username: %w", err)
	}
	password, err := b.GeneratePassword(ctx, config)
	if err != nil {
		return nil, err
	}

	templateData := dynamicTemplateData{
		Username:    username,
		Password:    password,
		DisplayName: req.DisplayName,
		RoleName:    roleName,
	}

	createLDIF, err := applyTemplate(dRole.CreationLDIF, templateData)
	if err != nil {
		return nil, fmt.Errorf("failed to apply creation_ldif template: %w", err)
	}

	q.Q(createLDIF)

	entries, err := ldif.Parse(createLDIF)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated LDIF: %w", err)
	}
	reqs := []*ldap.AddRequest{}
	for _, req := range entries.Entries {
		var addReq *ldap.AddRequest
		if req.Add != nil {
			addReq = req.Add
		} else {
			// Attempt to convert the Entry to an AddRequest
			attributes := make([]ldap.Attribute, 0, len(req.Entry.Attributes))
			for _, entryAttribute := range req.Entry.Attributes {
				attribute := ldap.Attribute{
					Type: entryAttribute.Name,
					Vals: entryAttribute.Values,
				}
				attributes = append(attributes, attribute)
			}
			addReq = &ldap.AddRequest{
				DN:         req.Entry.DN,
				Attributes: attributes,
				Controls:   nil,
			}
		}
		reqs = append(reqs, addReq)
	}

	q.Q(config.LDAP)

	successfulReqs, err := b.client.Add(config.LDAP, reqs...)
	q.Q(successfulReqs, err)
	if err != nil {
		// TODO: Handle rollback
		return nil, fmt.Errorf("failed to create LDAP entries: %w", err)
	}

	q.Q("Successful requests", len(successfulReqs))

	respData := map[string]interface{}{
		"username": username,
		"password": password,
		// TODO: dn?
	}
	internal := map[string]interface{}{}
	resp := b.Secret(secretCredsType).Response(respData, internal)
	resp.Secret.TTL = dRole.DefaultTTL
	resp.Secret.MaxTTL = dRole.MaxTTL

	return resp, nil
}

func (b *backend) secretCredsRevoke() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		q.Q("pathDynamicCredsDelete called!", data.Raw)
		return nil, fmt.Errorf("revoke not implemented")
	}
}

type usernameTemplateData struct {
	DisplayName string
	RoleName    string
}

func generateUsername(req *logical.Request, role *dynamicRole) (string, error) {
	if role.UsernameTemplate == "" {
		randStr, err := base62.Random(20)
		if err != nil {
			return "", err
		}
		username := fmt.Sprintf("v_%s_%s_%s_%d", req.DisplayName, role.Name, randStr, time.Now().Unix())
		return username, nil
	}
	tmpl, err := template.NewTemplate(
		template.Template(role.UsernameTemplate),
	)
	if err != nil {
		return "", err
	}
	usernameData := usernameTemplateData{
		DisplayName: req.DisplayName,
		RoleName:    role.Name,
	}
	return tmpl.Generate(usernameData)
}

type dynamicTemplateData struct {
	Username    string
	Password    string
	DisplayName string
	RoleName    string
}

func applyTemplate(rawTemplate string, data dynamicTemplateData) (string, error) {
	tmpl, err := template.NewTemplate(
		template.Template(rawTemplate),
	)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}
	str, err := tmpl.Generate(data)
	if err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return str, nil
}
