#include "apr_strings.h"
#include "apr_md5.h"
#include "apr_time.h"
#include "apr_lib.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
/*
auth_token_vp9_module
code by: tanmv
last update: 2015-04-06
*/

typedef struct {
	int enable;
	char *secret;	
	char *prefix;
	char *cookie_name;
	char *extension;
	unsigned int prefix_len;
	int timeout;
	int checkip;
} auth_token_config_rec;

static void *create_auth_token_vp9_dir_config(apr_pool_t *p, char *d)
{
	auth_token_config_rec *conf = apr_palloc(p, sizeof(*conf));
	conf->enable=1;
	conf->secret = NULL;
	conf->prefix = NULL;
	conf->cookie_name=NULL;
	conf->extension=NULL;
	conf->prefix_len = 0;
	conf->timeout = 600;
    conf->checkip = 0;
	return conf;
}

static const char *auth_token_set_prefix_slot(cmd_parms *cmd, void *config, const char *arg)
{
	int len = strlen(arg);
	auth_token_config_rec *conf = (auth_token_config_rec*)config;

	if (arg[len - 1] != '/') {
		ap_set_string_slot(cmd, config, apr_pstrcat(cmd->pool, arg, "/", NULL));
		conf->prefix_len = len + 1;
	}
	else {
		ap_set_string_slot(cmd, config, arg);
		conf->prefix_len = len;
	}

	return NULL;
}

static const command_rec auth_token_vp9_cmds[] =
{
	AP_INIT_FLAG("Enable", ap_set_flag_slot,(void *)APR_OFFSETOF(auth_token_config_rec, enable),ACCESS_CONF, "VP9 token: enable or disable moddule (Enable=on|off)"),
	AP_INIT_TAKE1("AuthTokenSecret", ap_set_string_slot,(void *)APR_OFFSETOF(auth_token_config_rec, secret),ACCESS_CONF, "VP9 token: config key xac thu (AuthTokenSecret=\"....\")"),
	AP_INIT_TAKE1("AuthTokenPrefix", auth_token_set_prefix_slot,(void *)APR_OFFSETOF(auth_token_config_rec,prefix),ACCESS_CONF, "VP9 token: config thu muc (AuthTokenPrefix=\"/chn/\")"),
	AP_INIT_TAKE1("CookieName", ap_set_string_slot,(void *)APR_OFFSETOF(auth_token_config_rec,cookie_name),ACCESS_CONF, "VP9 token: Hay nhap ten cookie (CookieName=\"token_key\")"),
	AP_INIT_TAKE1("Extension", ap_set_string_slot,(void *)APR_OFFSETOF(auth_token_config_rec,extension),ACCESS_CONF, "VP9 token: Hay nhap duoi mo rong (Extension=\"ts\")"),
	AP_INIT_TAKE1("AuthTokenTimeout", ap_set_int_slot,(void *)APR_OFFSETOF(auth_token_config_rec, timeout),ACCESS_CONF, "VP token: Hay nhap thoi gian (AuthTokenTimeout=600)"),
	AP_INIT_FLAG("AuthTokenLimitByIp", ap_set_flag_slot,(void *)APR_OFFSETOF(auth_token_config_rec, checkip),ACCESS_CONF, "VP9 token: enable or disable ip checking (AuthTokenLimitByIp=on|off)"),
	{NULL}
};

module AP_MODULE_DECLARE_DATA auth_token_vp9_module;

/*
 * Converts 8 hex digits to a timestamp
 */
static unsigned int auth_token_hex2sec(const char *x)
{
	int i, ch;
	unsigned int j;

	for (i = 0, j = 0; i < 8; i++) {
		ch = x[i];
		j <<= 4;

		if (apr_isdigit(ch))
			j |= ch - '0';
		else if (apr_isupper(ch))
			j |= ch - ('A' - 10);
		else
			j |= ch - ('a' - 10);
	}

	return j;
}

/*
 * Converts a binary string to hex
 */
static void auth_token_bin2hex(char *result, const char *x, int len)
{
	int i, ch;
	for (i = 0; i < len; i++) {
		ch = (x[i] & 0xF0) >> 4;
		if (ch < 10)
			result[i * 2] = '0' + ch;
		else
			result[i * 2] = 'A' + (ch - 10);

		ch = x[i] & 0x0F;
		if (ch < 10)
			result[i * 2 + 1] = '0' + ch;
		else
			result[i * 2 + 1] = 'A' + (ch - 10);
	}
}

static char *get_filename_ext(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if(!dot || dot == filename) return "";
    return dot + 1;
}

/*
static char *get_filename(const char *filename) {
    char *pLastSlash = strrchr(filename, '/');
    char *pszBaseName = pLastSlash ? pLastSlash + 1 : filename;
    return pszBaseName;
}
*/
/*
static char *get_director_name(const char *filename) {
	if(filename!=NULL){
		char* content_Slash = strtok(filename,"/");
		if(content_Slash){
			int n = strlen(filename);
			int i,k=-1;
			for(i=n-1;i>=0;i--){				
				if(filename[i]=='/'){
					k=i;
					break;
				}
			}
			if(k>=0){
				char* forlder;
				strncpy(forlder,filename,k);
				return forlder;
			}
		}
	}
	return "";
}
*/
//main request
static int authenticate_token(request_rec *r)
{
	//APLOG_ERR | APLOG_WARNING | APLOG_DEBUG | APLOG_NOTICE | APLOG_EMERG
	
	auth_token_config_rec *conf;	
	//if(!conf->enable) return DECLINED; //if not enable
	const char *remoteip;
	
	conf = ap_get_module_config(r->per_dir_config, &auth_token_vp9_module);
	
	// Get the remote IP , forcing to get an IP instead DNS record
	if (conf->checkip) {
		remoteip = ap_get_remote_host(r->connection, NULL, REMOTE_NAME, NULL);
    	if(NULL == remoteip)
		{
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "mod_token_vp9: request from ip is null (137) => DECLINED");
			return DECLINED;
		}
	}
	
	// check if the request uri is to be protected
	if (conf->prefix == NULL || strncmp(r->uri, conf->prefix, conf->prefix_len)) {
		return DECLINED;
	}
	
	//check extension file get via uri
	char* filename = r->uri;
	if(filename && filename!=NULL){
		char*extension = get_filename_ext(filename);
		if(strcmp(extension,conf->extension)!=0){
			return DECLINED;
		}
		else{
			//continue
		}
	}
	else{
		return DECLINED;
	}
		
	char* cookie_data = (char*)apr_table_get( r->headers_in, "Cookie");
	//const char* cookie_name;	
	const char* cookie_value;
	
	//strcpy(cookie_name,conf->cookie_name);//not run in ubuntu x64??
	
	if (cookie_data && cookie_data != NULL) {
		char* cookie_data_in = strdup(cookie_data);
		char* arr_cookie_values = strtok(cookie_data_in, ";");
		if(arr_cookie_values){
			while(arr_cookie_values) {
				char* cookie_item_in = strdup(arr_cookie_values);
				//char *content_key = strstr(cookie_item_in, strcat(cookie_name,"="));
				char *content_key = strstr(cookie_item_in, "token_key=");
				if(content_key!=NULL){
					//cookie_value = content_key + strlen(conf->cookie_name) + 1;
					cookie_value = content_key + 10;
				}
				arr_cookie_values = strtok(NULL, ";");
			}
		}
	}
	else{
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "mod_token_vp9: request: %s; cookie: null (183) => HTTP_UNAUTHORIZED",r->uri);
		//r->filename = "";
		return HTTP_UNAUTHORIZED;
	}
	
	if(strcmp(cookie_value,"")==0){
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "mod_token_vp9: request: %s; cookie: is null (189) => HTTP_UNAUTHORIZED",r->uri);
		//r->filename = "";
		return HTTP_UNAUTHORIZED;
	}
	
	//cookie format: timastamp+md5+user_id | 8 + 32 + ...
	
	if(strlen(cookie_value)<(8+32)){
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "mod_token_vp9: request: %s; cookie: %s, strlen(cookie) < 8+32 (196) => HTTP_UNAUTHORIZED",r->uri,cookie_value);
		//r->filename = "";
		return HTTP_UNAUTHORIZED;
	}
	
	const char *usertoken, *timestamp, *path, *user_id;
	unsigned char digest[APR_MD5_DIGESTSIZE];
	char token[APR_MD5_DIGESTSIZE * 2];
	apr_md5_ctx_t context;
	
	//cookie_value=timestamp+md5+user_id
	timestamp = cookie_value;
	usertoken = cookie_value + 8;
	user_id = cookie_value + 8 + 32;
	
	// check neu token het han
	if ((unsigned int)apr_time_sec(apr_time_now()) > auth_token_hex2sec(timestamp) + conf->timeout) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "mod_token_vp9: user_id: %s, token het han luc %u, hien tai %u (214) => HTTP_GONE", user_id, auth_token_hex2sec(timestamp) + conf->timeout, (unsigned int)apr_time_sec(apr_time_now()));
		return HTTP_GONE;
	}
	
	// create md5 token: usertoken = md5(conf->secret + filename + timestamp + user_id)
	// create md5 token check ip: usertoken = md5(conf->secret + filename + timestamp + user_id + remoteip)
	apr_md5_init(&context);
	apr_md5_update(&context, (unsigned char *) conf->secret, strlen(conf->secret));
	//apr_md5_update(&context, (unsigned char *) filename, strlen(filename));
	apr_md5_update(&context, (unsigned char *) timestamp, 8);
	apr_md5_update(&context, (unsigned char *) user_id, strlen(user_id));
	if (conf->checkip) apr_md5_update(&context, (unsigned char *) remoteip, strlen(remoteip));
	apr_md5_final(digest, &context);
	
	// compare hex encoded token and user provided token
	auth_token_bin2hex(token, (const char *)digest, APR_MD5_DIGESTSIZE);
	
	if (strncasecmp(token, usertoken, APR_MD5_DIGESTSIZE * 2) == 0) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "mod_token_vp9: token ok, user_id=%s, uri: %s (232) => DECLINED",user_id, r->uri);
		return DECLINED;
	}
	else{
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "mod_token_vp9: token sai, user_id=%s, token_input: '%s', token_done: '%s', uri: %s (236) => HTTP_FORBIDDEN ",user_id, apr_pstrndup(r->pool, usertoken, 32), apr_pstrndup(r->pool, token, 32), r->uri);
		return HTTP_FORBIDDEN;
	}
}

static void register_hooks(apr_pool_t *p)
{
	static const char * const aszPost[] = { "mod_alias.c", NULL };
	ap_hook_translate_name(authenticate_token, NULL, aszPost, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA auth_token_vp9_module =
{
	STANDARD20_MODULE_STUFF,
	create_auth_token_vp9_dir_config,	/* dir config creater */
	NULL,							    /* dir merger --- default is to override */
	NULL,							    /* server config */
	NULL,							    /* merge server config */
	auth_token_vp9_cmds,				/* command apr_table_t */
	register_hooks					    /* register hooks */
};