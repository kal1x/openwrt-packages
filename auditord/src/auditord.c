#include "auditord.h"
#include <sys/resource.h>


// ��־����
static int debug_enable = 1;
// ȫ���ļ���������������ں˷��͵�Ӧ�ò������
static int g_auditor_fd = -1;
//����������������ͨ��
static int g_socket_fd = -1;
static struct sockaddr_in  g_address = {0};//��������ͨ�ŵĵ�ַ

// �������ȫ�ֿ��أ�����һֱ�ظ�ȥ�������ļ�
static bool g_audit_switch = false ;

// ������ip��ַ�Ͷ˿�
static char g_server_ip[AUDITOR_MAX_IP_SIZE] = {0};
static uint32_t g_server_port = 0;


static ftp_list_t      g_ftp_list;
static telnet_list_t   g_telnet_list;
static ssid_list_t     g_ssid_list;

/* ���������� */
static pthread_mutex_t      ftp_list_mutex;
static pthread_mutex_t      telnet_list_mutex;
static pthread_mutex_t      ssid_list_mutex;


static int audit_send_async_event( audit_event_desc_s *p_event );


/* ������ƿ��� */
static inline void set_audit_switch(bool state)
{
    g_audit_switch = state ;
}

/* ��ȡ��ƿ��� */
static inline bool get_audit_switch( void )
{
    return g_audit_switch ;
}


static unsigned char a2x(const char c)
{
    switch (c) {
    case '0'...'9':
        return (unsigned char)atoi(&c);
    case 'a'...'f':
        return 0xa + (c-'a');
    case 'A'...'F':
        return 0xa + (c-'A');
    default:
        goto error;
    }
error:
    exit(0);
}


static inline bool is_valid_string(const char *str)
{
    struct in_addr addr;
    if (!str) {
        return false;
    }
    if (inet_aton(str, &addr) == 0) {
        return false;
    }
    return true;
}


char *audit_trim(char *str)
{
    if (!str) {
        return NULL;
    }

    while (IS_SPACE(*str)) str++;
    int len = strlen(str);
    if (!len) {
        return str;
    }

    char *end = str + len - 1;
    while (IS_SPACE(*end)) end--;
    *(++end) = '\0';

    return str;
}



int auditor_send_ftp_message(int fd, struct sockaddr_in *p_addr)
{
    int ret = -1;
    ftp_node_t *p_node = NULL;
    auditor_msg_t audit_msg = {0};
    ftp_msg_t *p_ftp_msg = NULL;

    DEBUG("[%s]: ==>start!\n", __func__);
    if (!p_addr) {
        return -1;
    }


    AUDIT_METUX_LOCK(ftp_list_mutex);

    p_node = g_ftp_list.next;
    while (p_node != &g_ftp_list) {
        memset(&audit_msg, 0, sizeof(auditor_msg_t));
        audit_msg.info_type = AUDITOR_MSG_TYPE_FTP;
        p_ftp_msg = (ftp_msg_t *)audit_msg.info;
        strncpy(p_ftp_msg->cmd, p_node->cmd, strlen(p_node->cmd));
        strncpy(p_ftp_msg->username, p_node->username,strlen(p_node->username));
        strncpy(p_ftp_msg->password, p_node->password,strlen(p_node->password));

        ret = sendto(fd, (char *)&audit_msg, sizeof(auditor_msg_t),0,(struct sockaddr *)p_addr,sizeof(*p_addr));
        if (ret < 0) {
            DEBUG("auditor_send_server_message failed , ret %d \n", ret);
            continue;
        }
        p_node = p_node->next;
    }

    AUDIT_METUX_UNLOCK(ftp_list_mutex);
    DEBUG("[%s]: <==finish!\n", __func__);
    return 0;
}


int auditor_send_telnet_message(int fd, struct sockaddr_in *p_addr)
{
    int ret = -1;
    telnet_node_t *p_node = NULL;
    auditor_msg_t audit_msg = {0};
    telnet_msg_t *p_telnet_msg = NULL;

    DEBUG("[%s]: ==>start!\n", __func__);
    if (fd <0 || !p_addr) {
        return -1;
    }

    AUDIT_METUX_LOCK(telnet_list_mutex);

    p_node = g_telnet_list.next;
    while (p_node != &g_telnet_list) {
        memset(&audit_msg, 0, sizeof(auditor_msg_t));
        audit_msg.info_type = AUDITOR_MSG_TYPE_TELNET;
        p_telnet_msg = (telnet_msg_t *)audit_msg.info;
        strncpy(p_telnet_msg->cmd, p_node->cmd, strlen(p_node->cmd));
        strncpy(p_telnet_msg->login, p_node->login,strlen(p_node->login));
        strncpy(p_telnet_msg->passwd, p_node->passwd,strlen(p_node->passwd));

        ret = sendto(fd, (char *)&audit_msg, sizeof(auditor_msg_t),0,(struct sockaddr *)p_addr,sizeof(*p_addr));
        if (ret < 0) {
            DEBUG("auditor_send_server_message failed , ret %d \n", ret);
            continue;
        }
        p_node = p_node->next;
    }

    AUDIT_METUX_UNLOCK(telnet_list_mutex);
    DEBUG("[%s]: <==finish!\n", __func__);
    return 0;
}


int auditor_send_ssid_message(int fd, struct sockaddr_in *p_addr)
{
    int ret = -1;

    ssid_node_t *p_node = NULL;
    auditor_msg_t audit_msg = {0};
    ssid_msg_t *p_ssid_msg = NULL;

    DEBUG("[%s]: ==>start!\n", __func__);
    if (!p_addr) {
        return -1;
    }
    AUDIT_METUX_LOCK(ssid_list_mutex);

    p_node = g_ssid_list.next;
    while (p_node != &g_ssid_list) {
        // ����Ѿ����͹������ڼ�������
        if (p_node->has_send) {
            continue;
        }
        memset(&audit_msg, 0, sizeof(auditor_msg_t));
        audit_msg.info_type = AUDITOR_MSG_TYPE_SSID;
        p_ssid_msg = (ssid_msg_t *)audit_msg.info;
        strncpy(p_ssid_msg->ssid, p_node->ssid, strlen(p_node->ssid));
        memcpy(p_ssid_msg->ssid_mac, p_node->ssid_mac, MAC_LEN_IN_BYTE);
        //DEBUG("000000----> SSID : %s\n", p_node->ssid);
        //PRINT_MAC(p_node->ssid_mac);
        ret = sendto(fd, (char *)&audit_msg, sizeof(auditor_msg_t),0,(struct sockaddr *)p_addr,sizeof(*p_addr));
        if (ret < 0) {
            DEBUG("auditor_send_server_message failed , ret %d \n", ret);
            continue;
        }
        p_node->has_send = 1;            // ��ʾ�Ѿ�����
        p_node = p_node->next;
    }

    AUDIT_METUX_UNLOCK(ssid_list_mutex);

    DEBUG("[%s]: <==finish!\n", __func__);
    return 0;
}


static int auditor_send_server_message( audit_send_message_handler p_handler )
{
    DEBUG("[%s]: ==>start!\n", __func__);
    if (p_handler(g_socket_fd, &g_address) < 0) {
        DEBUG("auditor_send_server_message error\n");
        return -1;
    }
    DEBUG("[%s]: <==finish!\n", __func__);
    return 0;
}


/* clear expired global list node and send auditor message periodically */
static int audit_report_event(audit_send_message_handler p_handler)
{
    int ret = 0 ;
    DEBUG("[%s]: ==>start!\n", __func__);

    if ( !p_handler ) {
        DEBUG("[%s]: ==>p_handler is NULL !\n", __func__);
        ret = -1 ;
        goto fail;
    }
    DEBUG("go in FUNC:%s \n",__func__);
    if ( auditor_send_server_message( p_handler ) != 0 ) {
        DEBUG("[%s]: ==>auditor_send_server_message fail !\n", __func__);
        ret = -1 ;
        goto fail;
    }

fail:
    DEBUG("[%s]: <==finish!\n", __func__);
    return ret ;
}


static int audit_ftp_event_cb( void )
{
    int ret = 0 ;
    DEBUG("[%s]: ==>start!\n", __func__);

    CHECK_AUDIT_STATE_OR_EXIT();
    if ( audit_report_event(auditor_send_ftp_message) != 0 ) {
        DEBUG("[%s]: ==>audit_report_event error !\n", __func__);
        ret = -1 ;
        goto fail;
    }
fail:
    DEBUG("[%s]: ==>finished!\n", __func__);
    return ret ;

}

static int audit_telnet_event_cb( void )
{
    int ret = 0 ;
    DEBUG("[%s]: ==>start!\n", __func__);

    CHECK_AUDIT_STATE_OR_EXIT();
    if ( audit_report_event(auditor_send_telnet_message) != 0 ) {
        DEBUG("[%s]: ==>audit_report_event error !\n", __func__);
        ret = -1 ;
        goto fail;
    }

fail:
    DEBUG("[%s]: ==>finished!\n", __func__);
    return ret ;
}


static int audit_ssid_event_cb( void )
{
    int ret = 0 ;
    DEBUG("[%s]: ==>start!\n", __func__);

    CHECK_AUDIT_STATE_OR_EXIT();
    if ( audit_report_event(auditor_send_ssid_message) != 0 ) {
        DEBUG("[%s]: ==>audit_report_event error !\n", __func__);
        ret = -1 ;
        goto fail;
    }

fail:
    DEBUG("[%s]: ==>finished!\n", __func__);
    return ret ;
}



/* �������е��¼�֪ͨ������������һ��������֪ͨ��ͬ���¼�������ftp����telnet�¼�
*  ���ܻ�ͬʱ������������һ�������ͻ�����������ͬ���¼���ͬʱ���͡�������һ������
*  ����¼һ���¼������ⲻ��Ҫ������*/

static audit_event_desc_s   audit_ftp_event= {
    .cb = audit_ftp_event_cb,
};
static audit_event_desc_s   audit_telnet_event= {
    .cb = audit_telnet_event_cb,
};
static audit_event_desc_s   audit_ssid_event= {
    .cb = audit_ssid_event_cb,
};



/* ��ȡ�����ļ��е�ѡ��Զ�Ӧ��ֵ */
/**********************************
*  �����ļ�����:
*  config bsac auditor
*       option disabled '1'
*       option ...
*  ���� auditor�� section ���� Ҳ���ǵ�һ������
*  ���� disabled��option ���֣�Ҳ���ǵڶ�������
*  ����ֵΪchar* ���û���ҵ���ΪNULL
*/
static char *auditord_get_option_value(const char *p_sec_name,
    const char *p_option_name)
{
    int len = 0;
    char *p_value = NULL;
    char command[MAXLINE] = {0};
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_element *p_element;

    if (!p_sec_name || !p_option_name) {
        return NULL;
    }
    ctx = uci_alloc_context();  /* register a context */
    if (UCI_OK != uci_load(ctx, AC_AUDITORD_CONFIG_FILE, &pkg)) {
        DEBUG("[%s]: call uci_load fail!\n", __func__);
        goto cleanup;
    }

    uci_foreach_element(&pkg->sections, p_element) {
        struct uci_section *p_section = uci_to_section(p_element);

        if (strncmp(p_sec_name, p_section->e.name, strlen(p_sec_name))) {
            /* not searched section */
            continue;
        }

        /* look up the option */
        p_value = (char *)uci_lookup_option_string(ctx, p_section, p_option_name);
        break;
    }

    uci_unload(ctx, pkg);

cleanup:
    uci_free_context(ctx);

    return p_value;
}



/* �������ļ��ж�ȡ����ֵ���ɹ�����0 ���򷵻� -1 */
static int auditord_config_get_integer_value(const char *p_sec_name,
    const char *p_option_name,int *p_value)
{
    char *p_val = auditord_get_option_value(p_sec_name,p_option_name);
    if ( NULL != p_val ) {
        *p_value = atoi(p_val);
        return 0 ;
    }
    return -1 ;
}



/* �������ļ��ж�ȡ�ַ���ֵ���ɹ�����0 ���򷵻� -1 */
//����޸�����:����ָ����ȡ�ļ�·��
//�޸�ʱ��2015-11-2
static int auditord_config_get_string_value(const char *p_sec_name,
    const char *p_option_name,char *p_value, uint32_t maxsize)
{
    char *p_val = auditord_get_option_value(p_sec_name,p_option_name);

    if ( NULL != p_val || strlen(p_val) +1 > maxsize) {
        strncpy(p_value,p_val,strlen(p_val));
        return 0 ;
    }
    return -1 ;
}


/**********************************************/
/*�޸������ļ�:
* p_pkg_name : Ҫ�޸ĵ������ļ�������
* p_sec_name : Ҫ�޸ĵ������ļ���section������
* p_option_name : Ҫ�޸ĵ������ļ���option������
* p_value : Ҫ�޸ĵ�ѡ���ֵ
* û�и�ѡ���򴴽� �� �ɹ��򷵻�0 ���򷵻�-1*/
/**********************************************/
static int auditord_change_config_value(const char *p_pkg_name,
    const char *p_sec_name, const char *p_option_name,const char *p_value)
{

    struct uci_ptr ptr ;
    char buf[512] = {0};
    struct uci_element *e = NULL;

    struct uci_context *ctx = uci_alloc_context();  //����������
    sprintf(buf,"%s.%s.%s=%s",p_pkg_name,p_sec_name,p_option_name,p_value);

    if (uci_lookup_ptr(ctx, &ptr, buf, true) != UCI_OK) {
        DEBUG("[%s]: error !\n", __func__);
        return -1;
    }
    e = ptr.last;                   //�Ƶ������ļ������
    uci_set(ctx,&ptr);              //д������
    uci_commit(ctx, &ptr.p, false);  //�ύ�������
    uci_unload(ctx,ptr.p);          //ж�ذ�
    uci_free_context(ctx);          //�ͷ�������

    return 0;
}


/* add by xiejian 20150711 ,������2014-11-11  �����ı�ʾʱ����ַ���ת��Ϊʱ������
* �ɹ��򷵻�0 ���򷵻�-1 */
static int timestr2time(const char *p_str,time_t *p_timep )
{
    struct tm time;
    const char *pFormat = "%Y-%m-%d %H:%M:%S";

    if ( !p_str || !p_timep )
        return -1 ;

    // strptime�������ת��ʧ�ܻ᷵��  NULL
    if ( !strptime(p_str, pFormat, &time) ) {
        return -1;
    }
    *p_timep = mktime(&time);
    return 0 ;
}


void auditor_add_ftp_info_list(ftp_info_t *p_info)
{
    int end = 0;
    ftp_node_t *p_new  = NULL;
    ftp_node_t *p_node = NULL;
    time_t now_time = time(NULL);
    bool utf8 = true;
    char tmp_utf8[1024] = {0};

    DEBUG("[%s]: ==>start!\n", __func__);

    if (!p_info) {
        DEBUG("[%s]: ERROR! p_info is NULL!\n", __func__);
        return ;
    }


    AUDIT_METUX_LOCK(ftp_list_mutex);
    p_node = g_ftp_list.next;

    DEBUG("p_info->src_mac = %x\n", *(int *)p_info->src_mac);
    DEBUG("p_info->src_ip = %1d\n", p_info->src_ip);
    DEBUG("p_info->src_port = %d\n", p_info->src_port);
    DEBUG("p_info->dst_ip = %1d\n", p_info->dst_ip);
    DEBUG("p_info->username = %s\n", p_info->username);
    DEBUG("p_info->password = %s\n", p_info->password);
    DEBUG("p_info->cmd = %s\n", p_info->cmd);

    while (p_node != &g_ftp_list) {
        if (!memcmp(p_node->src_mac, p_info->src_mac, MAC_LEN_IN_BYTE)
            && p_node->src_ip == p_info->src_ip
            && p_node->src_port == p_info->src_port
            && p_node->dst_ip == p_info->dst_ip) {
            end = strlen(p_node->cmd);
            // modify by xiejian 20141224 ��ftp����buffer�������
            if ( end + strlen(p_info->cmd) < FTP_CMD_LINE_LEN - 2 ) {
                p_node->cmd[end] = ',';
                strncpy(&p_node->cmd[end + 1], p_info->cmd, strlen(p_info->cmd));
            } else {
                memset(p_node->cmd,0,FTP_CMD_LINE_LEN);
                strncpy(p_node->cmd,p_info->cmd, strlen(p_info->cmd));
            }

            p_node->last_time = now_time;
            break;
        }

        p_node = p_node->next;
    }

    if (p_node == &g_ftp_list) {
        p_new = (ftp_node_t *)malloc(sizeof(ftp_node_t));
        if (!p_new) {
            DEBUG("[%s]: call malloc fail!\n", __func__);
            AUDIT_METUX_UNLOCK(ftp_list_mutex);
            return ;
        }
        memset(p_new, 0, sizeof(ftp_node_t));

        memcpy(p_new->src_mac, p_info->src_mac, MAC_LEN_IN_BYTE);
        p_new->src_ip = p_info->src_ip;
        p_new->src_port = p_info->src_port;
        p_new->dst_ip = p_info->dst_ip;
        strncpy(p_new->username, p_info->username, strlen(p_info->username));
        strncpy(p_new->password, p_info->password, strlen(p_info->password));
        strncpy(p_new->cmd, p_info->cmd, strlen(p_info->cmd));
        p_new->first_time = p_new->last_time = now_time;//changed 2014-12-04
        DEBUG("[%s]==>last_time:%ld\n",__func__,p_node->last_time);
        /*�̻����� ��ҪĿ�Ķ˿ڵ���Ϣ add by zhiyuan 2015-4-15*/
        p_new->dst_port = p_info->dst_port;


        /* add to id list tail */
        p_new->pre  = g_ftp_list.pre;
        p_new->next = &g_ftp_list;
        g_ftp_list.pre->next = p_new;
        g_ftp_list.pre = p_new;
    }

    AUDIT_METUX_UNLOCK(ftp_list_mutex);
    // ֪ͨ������Ϣ�߳̿�ʼ������Ϣ
    audit_send_async_event(&audit_ftp_event);

    DEBUG("[%s]: <==finish!\n", __func__);
    return;
}


void auditor_add_telnet_info_list(telnet_info_t *p_info)
{
    int end = 0;
    telnet_node_t *p_new = NULL;
    telnet_node_t *p_node = NULL;
    time_t now_time = time(NULL);

    DEBUG("[%s]: ==>start!\n", __func__);


    if (!p_info) {
        DEBUG("[%s]: ERROR! p_info is NULL!\n", __func__);
        return ;
    }

    AUDIT_METUX_LOCK(telnet_list_mutex);
    DEBUG("p_info->src_mac = %x\n", *(int *)p_info->src_mac);
    DEBUG("p_info->src_ip = %1d\n", p_info->src_ip);
    DEBUG("p_info->src_port = %d\n", p_info->src_port);
    DEBUG("p_info->dst_ip = %1d\n", p_info->dst_ip);
    DEBUG("p_info->login = %s\n", p_info->login);
    DEBUG("p_info->passwd = %s\n", p_info->passwd);
    DEBUG("p_info->cmd = %s\n", p_info->cmd);
    p_node = g_telnet_list.next;
    while (p_node != &g_telnet_list) {
        if (!memcmp(p_node->src_mac, p_info->src_mac, MAC_LEN_IN_BYTE)
            && p_node->src_ip == p_info->src_ip
            && p_node->src_port == p_info->src_port
            && p_node->dst_ip == p_info->dst_ip) {
            end = strlen(p_node->cmd);
            // modify by xiejian 20141224 ��ftp����buffer�������
            if ( end + strlen(p_info->cmd) < FTP_CMD_LINE_LEN - 2 ) {
                p_node->cmd[end] = ',';
                strncpy(&p_node->cmd[end + 1], p_info->cmd, strlen(p_info->cmd));
            } else {
                memset(p_node->cmd,0,FTP_CMD_LINE_LEN);
                strncpy(p_node->cmd,p_info->cmd, strlen(p_info->cmd));
            }
            p_node->last_time = now_time;
            break;
        }

        p_node = p_node->next;
    }

    if (p_node == &g_telnet_list) {
        p_new = (telnet_node_t *)malloc(sizeof(telnet_node_t));
        if (!p_new) {
            DEBUG("[%s]: call malloc fail!\n", __func__);
            AUDIT_METUX_UNLOCK(telnet_list_mutex);
            return ;
        }
        memset(p_new, 0, sizeof(telnet_info_t));

        memcpy(p_new->src_mac, p_info->src_mac, MAC_LEN_IN_BYTE);
        p_new->src_ip = p_info->src_ip;
        p_new->src_port = p_info->src_port;
        p_new->dst_ip = p_info->dst_ip;
        strncpy(p_new->login, p_info->login, strlen(p_info->login));
        strncpy(p_new->passwd, p_info->passwd, strlen(p_info->passwd));
        strncpy(p_new->cmd, p_info->cmd, strlen(p_info->cmd));
        p_new->first_time = p_new->last_time = now_time;//changed 2014-12-04

        /*�̻����� ��ҪĿ�Ķ˿ڵ���Ϣ add by zhiyuan 2015-4-15*/
        p_new->dst_port = p_info->dst_port;

        /* add to id list tail */
        p_new->pre  = g_telnet_list.pre;
        p_new->next = &g_telnet_list;
        g_telnet_list.pre->next = p_new;
        g_telnet_list.pre = p_new;
    }

    AUDIT_METUX_UNLOCK(telnet_list_mutex);
    // ֪ͨ������Ϣ�߳̿�ʼ������Ϣ
    audit_send_async_event(&audit_telnet_event);


    DEBUG("[%s]: <==finish!\n", __func__);
    return;
}


/* ap create socket for collecting ue macs from netlink */
int auditor_open_netlink_listen(int protocal)
{
    int ret = -1;
    int sock_fd;
    struct sockaddr_nl src_addr;

    sock_fd = socket(AF_NETLINK, SOCK_RAW, protocal);
    if (sock_fd < 0) {
        DEBUG("[%s]: call socket fail!\n", __func__);
        return -1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid    = 0;
    src_addr.nl_groups = 0;

    ret = bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));
    if (ret < 0) {
        DEBUG("[%s]: call bind fail!\n", __func__);
        close(sock_fd);
        return -1;
    }

    g_auditor_fd = sock_fd;
    return 0;
}


/* ap receive ue macs from netlink */
int auditor_receive_info_from_kernel(int socket_fd)
{
    int ret = -1;
    struct iovec iov;
    struct msghdr msg;
    struct nlmsghdr *nlh = NULL;
    auditor_info_t *p_info = NULL;

    DEBUG("[%s]: ==>start!\n", __func__);

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(AUDITOR_INFO_MAX_LEN));
    if (!nlh) {
        DEBUG("[%s]: call malloc fail!\n", __func__);
        return -1;
    }

    while (1) {
        memset(nlh, 0, NLMSG_SPACE(AUDITOR_INFO_MAX_LEN));
        iov.iov_base = (void *)nlh;
        iov.iov_len  = NLMSG_SPACE(AUDITOR_INFO_MAX_LEN);

        memset(&msg, 0, sizeof(msg));
        msg.msg_iov     = &iov;
        msg.msg_iovlen  = 1;

        ret = recvmsg(socket_fd, &msg, MSG_DONTWAIT);

        if (ret == 0)
            goto exit;/* ���������˳����쳣�˳� by zhiyuan 2015-4-8*/
        if ( ret == -1 && errno == EAGAIN )
            goto exit;
        if (ret < 0) {
            perror("recvmsg");
            //  printf("ret:%d>>>>>\n",ret);
            DEBUG("[%s]: call recvmsg fail!\n", __func__);
            goto exit;
        }

        p_info = (auditor_info_t *)NLMSG_DATA(nlh);
        if (!p_info) {
            DEBUG("[%s]: p_info is NULL!\n", __func__);
            goto exit;
        }
        DEBUG("[%s]:  p_info->info_type:%d \n", __func__,p_info->info_type);
        //printf("[%s]:  p_info->info_type:%d \n", __func__,p_info->info_type);
        switch ( p_info->info_type ) {
        case ENUM_AUDITOR_TYPE_TELNET:
            auditor_add_telnet_info_list((telnet_info_t *)p_info->info);
            break;
        case ENUM_AUDITOR_TYPE_FTP:
            auditor_add_ftp_info_list((ftp_info_t *)p_info->info);
            break;

        default:
            DEBUG("[%s]: not supported info type! info_type = %d\n", \
                __func__, p_info->info_type);
            break;
        }

    }

exit:
    if (nlh) {
        free(nlh);
    }

    DEBUG("[%s]: <==finish!\n", __func__);
    return 0;
}


void auditor_netlink_send_nlmsg(int socket_fd, int status)
{
    int ret = -1;
    struct iovec iov;
    struct msghdr msg;
    struct nlmsghdr *nlh = NULL;
    struct sockaddr_nl dst_addr;

    if (socket_fd <= 0) {
        DEBUG("[%s]: socket_fd is not ready!\n", __func__);
        return;
    }
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(int)));
    if (!nlh) {
        DEBUG("[%s]: call malloc fail!\n", __func__);
        return;
    }

    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.nl_family = AF_NETLINK;
    dst_addr.nl_pid    = 0;
    dst_addr.nl_groups = 0;

    nlh->nlmsg_len   = NLMSG_SPACE(sizeof(int));
    nlh->nlmsg_pid   = getpid();
    nlh->nlmsg_flags = 0;
    *(int *)NLMSG_DATA(nlh) = status;   /* ap_netlink switch ON/OFF */

    iov.iov_base = (void *)nlh;
    iov.iov_len  = NLMSG_SPACE(sizeof(int));

    memset(&msg, 0, sizeof(msg));
    msg.msg_name    = (void *)&dst_addr;
    msg.msg_namelen = sizeof(dst_addr);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    ret = sendmsg(socket_fd, &msg, 0);
    if (ret <= 0) {
        DEBUG("[%s]: call sendmsg fail!\n", __func__);
        goto exit;
    }

exit:
    if ( nlh ) {
        free(nlh);
        nlh = NULL;
    }

    return;
}


/* �����첽֪ͨ */
static int audit_send_async_event( audit_event_desc_s *p_event )
{
    int ret = 0 ;
    DEBUG("[%s]: ==>start!\n", __func__);
    if ( !p_event ) {
        DEBUG("[%s]: ==>p_event is NULL\n", __func__);
        ret = -1;
        goto fail;
    }
    AUDIT_METUX_LOCK(p_event->mutex);
    if ( p_event->has_event ) {
        DEBUG("[%s]: ==>has same event pending \n", __func__);
        ret = -1;
        goto hangup;
    }
    // �����߳�֮��ͨ�ţ������첽�¼�֪ͨ���Ǹı�ȫ�ֱ�����ֵ����ʾ�����¼�����
    p_event->has_event = true ;
hangup:
    AUDIT_METUX_UNLOCK(p_event->mutex);
fail:
    DEBUG("[%s]: <==finish!\n", __func__);
    return ret ;
}


/* ����һ������¼� */
static int audit_async_one_event( audit_event_desc_s *p_event )
{
    int ret = 0 ;
    //DEBUG("[%s]: ==>start!\n", __func__);
    if ( !p_event ) {
        DEBUG("[%s]: ==>p_event is NULL\n", __func__);
        ret = -1;
        goto fail;
    }
    AUDIT_METUX_LOCK(p_event->mutex);
    if ( p_event->has_event ) {
        p_event->has_event = false;
        p_event->cb() ;
    }
    AUDIT_METUX_UNLOCK(p_event->mutex);
fail:
    //DEBUG("[%s]: <==finish!\n", __func__);
    return ret ;
}


/* ��������첽֪ͨ���¼� ��ͳһ���������¼�*/
static int audit_async_all_events( void )
{
    //DEBUG("[%s]: ==>start!\n", __func__);
    if (audit_async_one_event(&audit_ftp_event) !=0 ||
        audit_async_one_event(&audit_telnet_event) !=0 ||
        audit_async_one_event(&audit_ssid_event) !=0) {
        DEBUG("[%s]: ==>async all events error !\n", __func__);
        return -1 ;
    }

    //DEBUG("[%s]: <==finish!\n", __func__);
    return 0 ;
}


/* ���ں��вɼ����ݵ��߳� */
static void collect_msg_form_kernel_thread( void )
{
    int  max_fd = 0;
    fd_set read_fd;
    struct timeval timeout = {0};
    DEBUG("[%s]: ==>start!\n", __func__);
    while (1) {
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;
        FD_ZERO(&read_fd);
        FD_SET(g_auditor_fd, &read_fd);
        max_fd = g_auditor_fd;
        switch (select(max_fd + 1, &read_fd, NULL, NULL, &timeout))     {
        case -1:            {
                /* Interrupted system call */
                DEBUG("[%s]: Call select fail! errno = %d\n", __func__, errno);
                break;
            }
        case 0:         {
                //DEBUG("[%s]: Timer expire when call select!\n", __func__);
                break;
            }
        default:            {
                // add by xiejian 20150609 , ����������ӷ�������ֱ�Ӿ����ں˷��͹�������Ϣ����������
                if (g_auditor_fd > 0 && FD_ISSET(g_auditor_fd, &read_fd))               {
                    DEBUG("[%s]:receive kernel info!\n",__func__);
                    auditor_receive_info_from_kernel(g_auditor_fd);
                }
            }
        }

    }


}


/* ������Ϣ�����������߳� */
static void send_msg_to_server_thread( void )
{

    int err=-1;
    struct timeval tv;
    uint64_t cur_time;
    DEBUG("[%s]: ==>start!\n", __func__);
    while (1) {
        tv.tv_sec=0;
        tv.tv_usec=300*1000;

        do {
            err=select(0,NULL,NULL,NULL,&tv);
            if (err < -1) {
                DEBUG("[%s]line=%d,err=%d\n", __func__, __LINE__,err);
            }
        } while (err<0 && errno==EINTR);

        if ( audit_async_all_events() != 0 ) {
            DEBUG("[%s]: audit_async_all_events error!\n", __func__);
        }
    }
}



static int init_all_mutex( void )
{

    if ( pthread_mutex_init(&telnet_list_mutex,NULL) != 0 ||
        pthread_mutex_init(&ftp_list_mutex,NULL) != 0 ||
        pthread_mutex_init(&ssid_list_mutex,NULL) != 0) {
        DEBUG("[%s]: Init metux error!\n", __func__);
        return -1;
    }

    if ( pthread_mutex_init(&audit_ftp_event.mutex,NULL) != 0 ||
        pthread_mutex_init(&audit_telnet_event.mutex,NULL) != 0 ||
        pthread_mutex_init(&audit_ssid_event.mutex,NULL) != 0) {
        DEBUG("[%s]: Init metux error!\n", __func__);
        return -1;
    }

    return 0 ;
}


void auditor_init_global()
{
    g_auditor_fd = -1;

    g_telnet_list.pre  = g_telnet_list.next  = &g_telnet_list;
    g_ftp_list.pre   = g_ftp_list.next   = &g_ftp_list;
    g_ssid_list.pre  = g_ssid_list.next  = &g_ssid_list;

    // Ĭ��������ƿ���Ϊ��
    set_audit_switch(false);

    if ( init_all_mutex() != 0 ) {
        DEBUG("[%s]: Init all metux error!\n", __func__);
    }
}


static int init_udp_socket( void )
{
    bzero(&g_address,sizeof(g_address));

    g_address.sin_family=AF_INET;
    g_address.sin_addr.s_addr=inet_addr(g_server_ip);//���ﲻһ��
    g_address.sin_port=htons(g_server_port);

    //����һ�� UDP socket
    g_socket_fd = socket(AF_INET,SOCK_DGRAM,0);
    if (g_socket_fd < 0) {
        DEBUG("create socket failed, sock_fd %d \n", g_socket_fd);
        return -1;
    }

    return 0;
}


static void auditor_clean_expire_ftp_list(void)
{
    ftp_node_t *p_node = NULL;
    ftp_node_t *p_next = NULL;
    time_t now_time = time(NULL);

    AUDIT_METUX_LOCK(ftp_list_mutex);

    p_node = g_ftp_list.next;
    while (p_node != &g_ftp_list) {
        if (now_time - p_node->last_time >= AUDIT_HISTORY_LIST_EXPIRED) {
            p_next = p_node->next;
            p_node->pre->next = p_node->next;
            p_node->next->pre = p_node->pre;
            free(p_node);

            p_node = p_next;
            continue;
        }

        p_node = p_node->next;
    }
    AUDIT_METUX_UNLOCK(ftp_list_mutex);
}


static void auditor_clean_expire_telnet_list(void)
{
    telnet_node_t *p_node = NULL;
    telnet_node_t *p_next = NULL;
    time_t now_time = time(NULL);

    AUDIT_METUX_LOCK(telnet_list_mutex);

    p_node = g_telnet_list.next;
    while (p_node != &g_telnet_list) {
        if (now_time - p_node->last_time >= AUDIT_HISTORY_LIST_EXPIRED) {
            p_next = p_node->next;
            p_node->pre->next = p_node->next;
            p_node->next->pre = p_node->pre;
            free(p_node);

            p_node = p_next;
            continue;
        }

        p_node = p_node->next;
    }
    AUDIT_METUX_UNLOCK(telnet_list_mutex);
}


static void auditor_clean_expire_ssid_list(void)
{
    ssid_node_t *p_node = NULL;
    ssid_node_t *p_next = NULL;
    time_t now_time = time(NULL);

    AUDIT_METUX_LOCK(ssid_list_mutex);

    p_node = g_ssid_list.next;
    while (p_node != &g_ssid_list) {

        if (now_time - p_node->last_time >= AUDIT_GUEST_SSID_LIST_EXPIRED) {
            p_next = p_node->next;
            p_node->pre->next = p_node->next;
            p_node->next->pre = p_node->pre;
            DEBUG("----------------------------------------> to clean ssid %s \n", p_node->ssid);
            PRINT_MAC(p_node->ssid_mac);
            free(p_node);

            p_node = p_next;
            continue;
        }
        p_node = p_node->next;
    }
    AUDIT_METUX_UNLOCK(ssid_list_mutex);
}


static int audit_clear_expire_list_callback(audit_clear_expire_list_handler p_handler)
{
    int ret = 0 ;
    //DEBUG("[%s]: ==>start!\n", __func__);

    if ( !p_handler ) {
        DEBUG("[%s]: ==>p_handler is NULL !\n", __func__);
        ret = -1 ;
        goto fail;
    }
    p_handler();
fail:
    //DEBUG("[%s]: <==finish!\n", __func__);
    return ret;
}


static void audit_clean_expire_list_cb(struct uloop_timeout *timeout)
{
    //DEBUG("[%s]: ==>start!\n", __func__);
    if (audit_clear_expire_list_callback(auditor_clean_expire_ftp_list) != 0 ||
        audit_clear_expire_list_callback(auditor_clean_expire_telnet_list) != 0 ||
        audit_clear_expire_list_callback(auditor_clean_expire_ssid_list) != 0) {
        DEBUG("[%s]: audit_clear_expire_list_callback error!\n", __func__);
    }
    if (timeout) {
        uloop_timeout_set(timeout, AUDIT_CLEAN_EXPIRE_LIST_INTERVAL);
    }
    //DEBUG("[%s]: <==finish!\n", __func__);
}

/* �����ʷ��¼����Ķ�ʱ�� */
static struct uloop_timeout audit_expire_timeout = {
    .cb = audit_clean_expire_list_cb,
};


/* �����ʷ��¼����̣߳�����������еĹ�ʱ����ʷ��¼ */
static void clean_expire_list_thread( void )
{
    int err=-1;
    struct timeval tv;

    while (1) {
        tv.tv_sec = AUDIT_CLEAN_EXPIRE_LIST_INTERVAL;
        tv.tv_usec=0;
        //DEBUG("[%s]: ==>start!\n", __func__);
        do {
            err=select(0,NULL,NULL,NULL,&tv);
            if (err < -1) {
                DEBUG("[%s]line=%d,err=%d\n", __func__, __LINE__,err);
            }
        } while (err<0 && errno==EINTR);

        //DEBUG("[%s]line=%d,err=%d\n", __func__, __LINE__,err);

        audit_clean_expire_list_cb(NULL);

        //DEBUG("[%s]: <==finish!\n", __func__);

    }
}

// ��ʽ���� 48:7D:2E:65:6F:03  ACB305�������ҵ���һ���ո��ַ�
static int parse_guest_ssid_and_mac(char *str)
{
    char *p = NULL, *ssid = NULL;
    ssid_node_t *p_new = NULL;
    ssid_node_t *p_node = NULL;
    time_t now_time = time(NULL);
    unsigned char macaddr[MAC_LEN_IN_BYTE + 2] = {0};

    p = strchr(str, ' ');
    if (!p) {
        return -1;
    }
    *p = '\0';
    p += 1;
    COPY_STR2MAC(macaddr, str);
    ssid = audit_trim(p);
    if (!ssid) {
        return -1;
    }
    // PRINT_MAC(macaddr);
    // DEBUG("----> ssid %s \n", ssid);
    AUDIT_METUX_LOCK(ssid_list_mutex);
    p_node = g_ssid_list.next;
    while (p_node != &g_ssid_list) {
        if (!memcmp(p_node->ssid_mac, macaddr, MAC_LEN_IN_BYTE)
            && !strncmp(p_node->ssid, ssid, strlen(ssid) )) {
            p_node->last_time = now_time;
            break;

        }
        p_node = p_node->next;
    }
    if (p_node == &g_ssid_list) {
        p_new = (ssid_node_t *)malloc(sizeof(ssid_node_t));
        if (!p_new) {
            DEBUG("[%s]: call malloc fail!\n", __func__);
            AUDIT_METUX_UNLOCK(ssid_list_mutex);
            return -1;
        }
        memset(p_new, 0, sizeof(ssid_node_t));
        memcpy(p_new->ssid_mac, macaddr, MAC_LEN_IN_BYTE);
        strncpy(p_new->ssid, ssid, strlen(ssid));
        p_new->last_time = now_time;
        p_new->has_send = 0;     // ��ʶ�Ƿ��Ѿ����ͣ�Ĭ��û����

        /* add to id list tail */
        p_new->pre  = g_ssid_list.pre;
        p_new->next = &g_ssid_list;
        g_ssid_list.pre->next = p_new;
        g_ssid_list.pre = p_new;
    }
    AUDIT_METUX_UNLOCK(ssid_list_mutex);

    return 0;
}


// ͨ��shell��������ȡguest ssid mac����Ϣ
static void scan_guest_ssid_from_shell( void )
{
    char buffer[512] = {0};
    FILE *pipe = popen(AUT_SCAN_WIFI_CMD, "r");
    if (!pipe) {
        return;
    }
    while (!feof(pipe)) {
        memset(buffer, 0, sizeof(buffer));
        if (fgets(buffer, sizeof(buffer), pipe)) {
            char *tmp = audit_trim(buffer);
            if (!tmp) {
                continue;
            }
            //DEBUG("--------> tmp : %s \n", tmp);
            parse_guest_ssid_and_mac(tmp);

        }
    }
    pclose(pipe);
    // ֪ͨ������Ϣ�߳̿�ʼ������Ϣ
    audit_send_async_event(&audit_ssid_event);

}


/* ����ͳ���ܱߵ�wifi   ssid����mac��ַ���߳�  */
static void scan_guest_ssid_thread( void )
{
    int err=-1;
    struct timeval tv;

    while (1) {
        tv.tv_sec = AUDIT_SCAN_GUEST_SSID_INTERVAL;
        tv.tv_usec=0;
        //DEBUG("[%s]: ==>start!\n", __func__);
        do {
            err=select(0,NULL,NULL,NULL,&tv);
            if (err < -1) {
                DEBUG("[%s]line=%d,err=%d\n", __func__, __LINE__,err);
            }
        } while (err<0 && errno==EINTR);

        //DEBUG("[%s]line=%d,err=%d\n", __func__, __LINE__,err);

        scan_guest_ssid_from_shell();

        //DEBUG("[%s]: <==finish!\n", __func__);

    }
}


/* �ɹ��򷵻�0 ���򷵻�0 */
static int create_four_thread( pthread_t *thread1,pthread_t *thread2,
    pthread_t *thread3, pthread_t *thread4 )
{
    int ret ;
    DEBUG("[%s]: ==>start!\n", __func__);
    if (!thread1 || !thread2 || !thread3 || !thread4) {
        return -1;
    }
    ret = pthread_create(thread1, NULL, (void *)&collect_msg_form_kernel_thread, NULL);
    if ( ret ) {
        DEBUG("[%s]: Create thread1 error !\n", __func__);
        return -1 ;
    }

    ret = pthread_create(thread2, NULL, (void *)&send_msg_to_server_thread, NULL);
    if ( ret ) {
        DEBUG("[%s]: Create thread2 error !\n", __func__);
        return -1 ;
    }

    ret = pthread_create(thread3, NULL, (void *)&clean_expire_list_thread, NULL);
    if ( ret ) {
        DEBUG("[%s]: Create thread3 error !\n", __func__);
        return -1 ;
    }
    ret = pthread_create(thread4, NULL, (void *)&scan_guest_ssid_thread, NULL);
    if ( ret ) {
        DEBUG("[%s]: Create thread4 error !\n", __func__);
        return -1 ;
    }
    DEBUG("[%s]: <==finish!\n", __func__);
    return 0 ;
}


/*
 *  ac switch on/off efence function when catch signal from web.
 */
void auditor_switch_auditor_function(int signo)
{
    char *tmp = NULL;
    int len = 0, enabled = 0;
    uint32_t port = 0;

    DEBUG("[%s]: ==>start!\n", __func__);

    /* read the audit switch status from /etc/config/audit */
    if ( auditord_config_get_integer_value("audit","enabled",&enabled) < 0 ||
        auditord_config_get_integer_value("audit","port",&g_server_port) < 0 ||
        auditord_config_get_string_value("audit", "serverip", g_server_ip, sizeof(g_server_ip)) < 0) {
        DEBUG("[%s]:  read the audit  /etc/config/audit  file error !\n", __func__);
    }
    DEBUG("[%s]: ==>enabled %d !\n", __func__,enabled);
    DEBUG("[%s]: ==>g_server_port %d !\n", __func__,g_server_port);
    DEBUG("[%s]: ==>g_server_ip %s !\n", __func__,g_server_ip);
    auditord_config_get_string_value("audit", "serverip", g_server_ip, sizeof(g_server_ip));

    // ���״̬�ı�
    if ( get_audit_switch() != enabled ) {
        // ����״̬�������ǰ�����ת��Ϊbool��
        set_audit_switch(!!enabled);
    }
    auditor_netlink_send_nlmsg(g_auditor_fd, enabled);

    DEBUG("[%s]: <==finish!\n", __func__);
}



static void auditor_setup_signals()
{
    struct sigaction s;

    memset(&s, 0, sizeof(s));
    s.sa_flags = 0;
    // ����ź������������ļ��Ķ�ȡ
    s.sa_handler = auditor_switch_auditor_function;
    sigaction(SIGUSR2, &s, NULL);
}


int main( void )
{
    char cmd[128] = {0};
    pthread_t collect_thread;             //�ɼ��߳�
    pthread_t sender_thread;              //�����߳�
    pthread_t clean_thread;               //��������߳�
    pthread_t scan_thread;                // iwinfo scan�߳�

    DEBUG("%s,%s,%s,%s\n", "auditord", ADT_VERSION,__DATE__,__TIME__);
    sprintf(cmd, "echo %d > %s", getpid(), AUDITORD_PID_FILE);
    system(cmd);

    auditor_init_global();

    /* init ue mac list, and open socket for ap_netlink */
    if (auditor_open_netlink_listen(NETLINK_AUDITOR_PROTO) != 0) {
        DEBUG("[%s]: LINE %d Call ap_open_netlink_listen fail!\n", __func__,__LINE__);
        return -1;
    }

    /* ע���źţ���һ�ζ�ȡʹ�ܿ��ض�ȡ�����ļ� */
    auditor_setup_signals();
    // ��ȡ�����ļ�
    auditor_switch_auditor_function(SIG_AC_READ_AUDITORD_CONF);

    if (init_udp_socket() < 0) {
        DEBUG("[%s]: LINE %d Call init_udp_socket fail!\n", __func__,__LINE__);
        return -1;
    }
    if ( get_audit_switch() ) {

        if ( create_four_thread(&collect_thread,&sender_thread,&clean_thread, &scan_thread) < 0 ) {
            DEBUG("[%s] LINE %d : Create thread fail!\n", __func__, __LINE__);
            return -1;
        }

        /* �ȴ��߳̽���*/
        pthread_join(collect_thread,NULL);
        pthread_join(sender_thread,NULL);
        pthread_join(clean_thread,NULL);
        pthread_join(scan_thread,NULL);
    }

    return 0;
}


