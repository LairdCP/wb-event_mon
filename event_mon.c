/*

Copyright (c) 2014, Laird

Permission to use, copy, modify, and/or distribute this software for any 
purpose with or without fee is hereby granted, provided that the above 
copyright notice and this permission notice appear in all copies.
THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES 
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF 
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY 
SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES 
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN 
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <syslog.h>
#include <string.h>
#include "sdc_sdk.h"

#define LRD_BLD_NUMBER  "10.0.0.103"

#define LRD_EVENT_MON_VERSION_MAJOR 3
#define LRD_EVENT_MON_VERSION_MINOR 5
#define LRD_EVENT_MON_VERSION_REVISION 2
#define LRD_EVENT_MON_VERSION_SUB_REVISION 2

void sigproc(int);
void quitproc(int);
void usage();
void cleanUp();

bool logging = false;
bool console = true;
bool outputLease = false;
bool manager = false;

bool fw_crash = false;
char BUFFER[20] = "                   ";

#define LRD_EVT_OutputString(...) {if(logging) syslog(LOG_INFO, __VA_ARGS__); if(console) printf(__VA_ARGS__);}

#define MAX_LTH_ETH 			18

const char *eventNames[SDC_E_MAX+1] = {
	"SDC_E_SET_SSID",
	"SDC_E_AUTH",
	"SDC_E_AUTH_IND",
	"SDC_E_DEAUTH",
	"SDC_E_DEAUTH_IND",
	"SDC_E_ASSOC",
	"SDC_E_ASSOC_IND",
	"SDC_E_REASSOC",
	"SDC_E_REASSOC_IND",
	"SDC_E_DISASSOC",
	"SDC_E_DISASSOC_IND",
	"SDC_E_QUIET_START",
	"SDC_E_QUIET_END",
	"SDC_E_BEACON_RX",
	"SDC_E_MIC_ERROR",
	"SDC_E_ROAM",
	"SDC_E_PMKID_CACHE",
	"SDC_E_ADDTS_IND",
	"SDC_E_DELTS_IND",
	"SDC_E_ROAM_PREP",
	"SDC_E_PSM_WATCHDOG",
	"SDC_E_PSK_SUP",
	"SDC_E_ICV_ERROR",
	"SDC_E_RSSI",
	"SDC_E_DHCP",
	"SDC_E_READY",
	"SDC_E_CONNECT_REQ",
	"SDC_E_CONNECT",
	"SDC_E_RECONNECT_REQ",
	"SDC_E_DISCONNECT_REQ",
	"SDC_E_DISCONNECT",
	"SDC_E_SCAN_REQ",
	"SDC_E_SCAN",
	"SDC_E_REGDOMAIN",
	"SDC_E_CMDERROR",
	"SDC_E_CONNECTION_STATE",
	"SDC_E_INTERNAL",
	"SDC_E_FW_ERROR",
	"SDC_E_AP_STA_CONNECT",
	"SDC_E_AP_STA_DISCONNECT",
	"SDC_E_MAX",
};

const char* eventToStr(int event)
{
	if (event <= SDC_E_MAX)
		return eventNames[event];

	sprintf(BUFFER, "0x%x", event);
	return BUFFER;
}

/* Event status codes */
const char* statusToStr( int status)
{
	switch(status)
	{
		case SDC_E_STATUS_SUCCESS : return "SDC_E_STATUS_SUCCESS"; break;
		case SDC_E_STATUS_FAIL : return " SDC_E_STATUS_FAIL"; break;
		case SDC_E_STATUS_TIMEOUT : return "SDC_E_STATUS_TIMEOUT"; break;
		case SDC_E_STATUS_NO_NETWORKS : return "SDC_E_STATUS_NO_NETWORKS"; break;
		case SDC_E_STATUS_ABORT : return "SDC_E_STATUS_ABORT"; break;
		case SDC_E_STATUS_NO_ACK : return "SDC_E_STATUS_NO_ACK"; break;
		case SDC_E_STATUS_UNSOLICITED : return "SDC_E_STATUS_UNSOLICITED"; break;
		case SDC_E_STATUS_ATTEMPT : return "SDC_E_STATUS_ATTEMPT"; break;
		case SDC_E_STATUS_PARTIAL : return "SDC_E_STATUS_PARTIAL"; break;
		case SDC_E_STATUS_NEWSCAN : return "SDC_E_STATUS_NEWSCAN"; break;
		case SDC_E_STATUS_NEWASSOC : return "SDC_E_STATUS_NEWASSOC"; break;
		case SDC_E_STATUS_11HQUIET : return "SDC_E_STATUS_11HQUIET"; break;
		case SDC_E_STATUS_SUPPRESS : return "SDC_E_STATUS_SUPPRESS"; break;
		case SDC_E_STATUS_NOCHANS : return "SDC_E_STATUS_NOCHANS"; break;
		case SDC_E_STATUS_CCXFASTRM : return "SDC_E_STATUS_CCXFASTRM"; break;
		case SDC_E_STATUS_CS_ABORT : return "SDC_E_STATUS_CS_ABORT"; break;
		default :
			sprintf(BUFFER, "%d", status);
			return BUFFER;
	}
}

const char* roamReasonToStr( int reason )
{
	switch(reason)
	{
		case SDC_E_REASON_INITIAL_ASSOC : return "SDC_E_REASON_INITIAL_ASSOC"; break;
		case SDC_E_REASON_LOW_RSSI : return "SDC_E_REASON_LOW_RSSI"; break;
		case SDC_E_REASON_DEAUTH : return "SDC_E_REASON_DEAUTH"; break;
		case SDC_E_REASON_DISASSOC : return "SDC_E_REASON_DISASSOC"; break;
		case SDC_E_REASON_BCNS_LOST : return "SDC_E_REASON_BCNS_LOST"; break;
		case SDC_E_REASON_FAST_ROAM_FAILED : return "SDC_E_REASON_FAST_ROAM_FAILED"; break;
		case SDC_E_REASON_DIRECTED_ROAM : return "SDC_E_REASON_DIRECTED_ROAM"; break;
		case SDC_E_REASON_TSPEC_REJECTED : return "SDC_E_REASON_TSPEC_REJECTED"; break;
		case SDC_E_REASON_BETTER_AP : return "SDC_E_REASON_BETTER_AP"; break;
		case SDC_E_REASON_UNSPECIFIED : return "SDC_E_REASON_UNSPECIFIED"; break;
		default :
			sprintf(BUFFER, "%d", reason);
			return BUFFER;
	}
}

const char* w80211ReasonToStr(unsigned int reason)
{
	switch(reason)
	{
		case DOT11_RC_RESERVED		    : return "DOT11_RC_RESERVED"; break;
		case DOT11_RC_UNSPECIFIED	    : return "DOT11_RC_UNSPECIFIED"; break;
		case DOT11_RC_AUTH_INVAL		: return "DOT11_RC_AUTH_INVAL"; break;
		case DOT11_RC_DEAUTH_LEAVING	: return "DOT11_RC_DEAUTH_LEAVING"; break;
		case DOT11_RC_INACTIVITY		: return "DOT11_RC_INACTIVITY"; break;
		case DOT11_RC_BUSY			    : return "DOT11_RC_BUSY"; break;
		case DOT11_RC_INVAL_CLASS_2		: return "DOT11_RC_INVAL_CLASS_2"; break;
		case DOT11_RC_INVAL_CLASS_3		: return "DOT11_RC_INVAL_CLASS_3"; break;
		case DOT11_RC_DISASSOC_LEAVING	: return "DOT11_RC_DISASSOC_LEAVING"; break;
		case DOT11_RC_NOT_AUTH		    : return "DOT11_RC_NOT_AUTH"; break;
		case DOT11_RC_BAD_PC			: return "DOT11_RC_BAD_PC"; break;
		case DOT11_RC_BAD_CHANNELS		: return "DOT11_RC_BAD_CHANNELS"; break;
		case DOT11_RC_BSS_TRANSIT_MGMT	: return "DOT11_RC_BSS_TRANSIT_MGMT"; break;
		case DOT11_RC_UNSPECIFIED_QOS	: return "DOT11_RC_UNSPECIFIED_QOS"; break;
		case DOT11_RC_INSUFFCIENT_BW	: return "DOT11_RC_INSUFFCIENT_BW"; break;
		case DOT11_RC_EXCESSIVE_FRAMES	: return "DOT11_RC_EXCESSIVE_FRAMES"; break;
		case DOT11_RC_TX_OUTSIDE_TXOP	: return "DOT11_RC_TX_OUTSIDE_TXOP"; break;
		case DOT11_RC_LEAVING_QBSS		: return "DOT11_RC_LEAVING_QBSS"; break;
		case DOT11_RC_BAD_MECHANISM		: return "DOT11_RC_BAD_MECHANISM"; break;
		case DOT11_RC_SETUP_NEEDED		: return "DOT11_RC_SETUP_NEEDED"; break;
		case DOT11_RC_TIMEOUT		    : return "DOT11_RC_TIMEOUT"; break;
		case DOT11_RC_INVALID_WPA_IE    : return "DOT11_RC_INVALID_WPA_IE"; break;
		case DOT11_RC_MIC_FAILURE		: return "DOT11_RC_MIC_FAILURE"; break;
		case DOT11_RC_4WH_TIMEOUT		: return "DOT11_RC_4WH_TIMEOUT"; break;
		case DOT11_RC_GTK_UPDATE_TIMEOUT: return "DOT11_RC_GTK_UPDATE_TIMEOUT"; break;
		case DOT11_RC_WPA_IE_MISMATCH	: return "DOT11_RC_WPA_IE_MISMATCH"; break;
		case DOT11_RC_INVALID_MC_CIPHER	: return "DOT11_RC_INVALID_MC_CIPHER"; break;
		case DOT11_RC_INVALID_UC_CIPHER	: return "DOT11_RC_INVALID_UC_CIPHER"; break;
		case DOT11_RC_INVALID_AKMP		: return "DOT11_RC_INVALID_AKMP"; break;
		case DOT11_RC_BAD_WPA_VERSION	: return "DOT11_RC_BAD_WPA_VERSION"; break;
		case DOT11_RC_INVALID_WPA_CAP	: return "DOT11_RC_INVALID_WPA_CAP"; break;
		case DOT11_RC_8021X_AUTH_FAIL	: return "DOT11_RC_8021X_AUTH_FAIL"; break;
		default :
			sprintf(BUFFER, "%d", reason);
			return BUFFER;
	}
}

const char* disconnectReasontoStr(SDC_ATH_DISCONNECT_REASON reason)
{
	switch(reason)
	{
		case DISCON_REASON_UNSPEC	: return "DISCON_REASON_UNSPEC"; break;
		case NO_NETWORK_AVAIL		: return "NO_NETWORK_AVAIL"; break;
		case LOST_LINK	    		: return "LOST_LINK"; break;
		case DISCONNECT_CMD			: return "DISCONNECT_CMD"; break;
		case BSS_DISCONNECTED		: return "BSS_DISCONNECTED"; break;
		case AUTH_FAILED			: return "AUTH_FAILED"; break;
		case ASSOC_FAILED			: return "ASSOC_FAILED"; break;
		case NO_RESOURCES_AVAIL		: return "NO_RESOURCES_AVAIL"; break;
		case CSERV_DISCONNECT		: return "CSERV_DISCONNECT"; break;
		case INVALID_PROFILE		: return "INVALID_PROFILE"; break;
		case DOT11H_CHANNEL_SWITCH	: return "DOT11H_CHANNEL_SWITCH"; break;
		case PROFILE_MISMATCH		: return "PROFILE_MISMATCH"; break;
		case CONNECTION_EVICTED		: return "CONNECTION_EVICTED"; break;
		case IBSS_MERGE				: return "IBSS_MERGE"; break;
		default :
			sprintf(BUFFER, "%d", reason);
			return BUFFER;
	}
}

const char* cmderrorReasontoStr(SDC_ATH_CMDERROR_REASON reason)
{
	switch(reason)
	{
		case INVALID_PARAM			: return "INVALID_PARAM"; break;
		case ILLEGAL_STATE			: return "ILLEGAL_STATE"; break;
		case INTERNAL_ERROR			: return "INTERNAL_ERROR"; break;
		default :
			sprintf(BUFFER, "%d", reason);
			return BUFFER;
	}
}

const char* authStatusToStr(LRD_WF_EvtAuthStatus status)
{
	switch(status)
	{
	case AUTH_STATUS_UNSPEC: return "AUTH_STATUS_UNSPEC"; break;
	case AUTH_STARTED:       return "AUTH_STARTED"; break;
	case AUTH_SUCCESS:       return "AUTH_SUCCESS"; break;
	case AUTH_FAILURE:       return "AUTH_FAILURE"; break;
	default:
		sprintf(BUFFER, "%d", status);
		return BUFFER;
	}
}

const char* authReasonToStr(LRD_WF_EvtAuthReason reason)
{
	switch(reason)
	{
	case AUTH_REASON_UNSPEC:   return "AUTH_REASON_UNSPEC"; break;
	case AUTH_SERVER_NO_RESP:  return "AUTH_SERVER_NO_RESP"; break;
	case INVALID_CREDENTIALS:  return "INVALID_CREDENTIALS"; break;
	case METHOD_NOT_SUPPORTED: return "METHOD_NOT_SUPPORTED"; break;
	case INVALID_CERT_PASS:    return "INVALID_CERT_PASS"; break;
	case FOUR_WAY_HAND_SHAKE_FAILURE: return "FAILURE IN 4-WAY HANDSHAKE"; break;
	case CERT_EXPIRED: return "CERT_EXPIRED"; break;
	case CERT_NOT_YET_VALID: return "CERT_NOT_YET_VALID"; break;
	case CERT_FAILURE_REASON_UNSPECIFIED: return "CERT_FAILURE_REASON_UNSPECIFIED"; break;
	default:
		sprintf(BUFFER, "%d", reason);
		return BUFFER;
	}
}

const char* evtConStatusToStr(LRD_WF_EvtConStatus status)
{
	switch(status)
	{
	case CON_STATUS_UNSPEC: return "CON_STATUS_UNSPEC"; break;
	case NOT_CONNECTED:     return "NOT_CONNECTED"; break;
	case ASSOCIATING:       return "ASSOCIATING"; break;
	case ASSOCIATED:        return "ASSOCIATED"; break;
	case ASSOC_ERROR:       return "ASSOC_ERROR"; break;
	case AUTHENTICATING:    return "AUTHENTICATING"; break;
	case AUTHENTICATED:     return "AUTHENTICATED"; break;
	case AUTH_ERROR:        return "AUTH_ERROR"; break;
	default:
		sprintf(BUFFER, "%d", status);
		return BUFFER;
	}
}

const char* dhcpStatusToStr(LRD_WF_EvtDHCPStatus status)
{
	switch(status)
	{
	case DHCP_STATUS_UNSPEC: return "DHCP_STATUS_UNSPEC"; break;
	case DECONFIG:          return "DECONFIG"; break;
	case REQUESTING:        return "REQUESTING"; break;
	case RENEWING:          return "RENEWING"; break;
	case RENEWED:           return "RENEWED"; break;
	case REBINDING:         return "REBINDING"; break;
	case BOUND:             return "BOUND"; break;
	case NAK:               return "NAK"; break;
	case LEASEFAIL:         return "LEASEFAIL"; break;
	case RELEASED:          return "RELEASED"; break;
	default:
		sprintf(BUFFER, "%d", status);
		return BUFFER;
	}
}

const char* dhcpReasonToStr(LRD_WF_EvtDHCPReason reason)
{
	switch(reason)
	{
	case DHCP_REASON_UNSPEC: return "DHCP_REASON_UNSPEC"; break;
	case IP_ADDRESS_SAME:    return "IP_ADDRESS_SAME"; break;
	case IP_ADDRESS_DIFFERENT:  return "IP_ADDRESS_DIFFERENT"; break;
	default:
		sprintf(BUFFER, "%d", reason);
		return BUFFER;
	}
}

const char* intStatusToStr(LRD_WF_EvtIntStatus status)
{
	switch(status)
	{
	case INT_STATUS_UNSPEC: return "INT_STATUS_UNSPEC"; break;
	case LOST_COM_DRV:      return "LOST_COM_DRV"; break;
	case LOST_COM_KERN:     return "LOST_COM_KERN"; break;
	case LOST_COM_SUPP:     return "LOST_COM_SUPP"; break;
	case LOST_COM_INJ:      return "LOST_COM_INJ"; break;
	default:
		sprintf(BUFFER, "%d", status);
		return BUFFER;
	}
}

const char* intReasonToStr(LRD_WF_EvtIntReason reason)
{
	switch(reason)
	{
	case INT_REASON_UNSPEC: return "INT_REASON_UNSPEC"; break;
	case COM_EXITED:        return "COM_EXITED"; break;
	case COM_ERROR:         return "COM_ERROR"; break;
	default:
		sprintf(BUFFER, "%d", reason);
		return BUFFER;
	}
}

const char* fwErrReasonToStr(LRD_WF_EvtFwErrorReason reason)
{
	switch(reason)
	{
	case FW_ASSERT:          return "FW_ASSERT"; break;
	case FW_HB_RESP_FAILURE: return "FW_HB_RESP_FAILURE"; break;
	case FW_EP_FULL:         return "FW_EP_FULL"; break;
	default:
		sprintf(BUFFER, "%d", reason);
		return BUFFER;
	}
}


const char* authModeToStr( int auth_type )
{
	switch(auth_type)
	{
		case AUTH_OPEN : return "AUTH_OPEN"; break;
		case AUTH_SHARED : return "AUTH_SHARED"; break;
		case AUTH_NETWORK_EAP : return "AUTH_NETWORK_EAP"; break;
		default :
			sprintf(BUFFER, "%d", auth_type);
			return BUFFER;
	}
}

const char *ether_ntoa(const sdc_ether_addr *ea, char *buf)
{
	snprintf(buf, MAX_LTH_ETH, "%02x:%02x:%02x:%02x:%02x:%02x",
			 ea->octet[0]&0xff, ea->octet[1]&0xff, ea->octet[2]&0xff,
			 ea->octet[3]&0xff, ea->octet[4]&0xff, ea->octet[5]&0xff);
	return (buf);
}

void outputDHCPLease(const DHCP_LEASE *dhcp)
{
	LRD_EVT_OutputString("interface:    %s\n",  dhcp->interface);
	LRD_EVT_OutputString("address:      %s\n",  dhcp->address);
	LRD_EVT_OutputString("subnet_mask:  %s\n",  dhcp->subnet_mask);
	LRD_EVT_OutputString("routers:      %s\n",  dhcp->routers);
	LRD_EVT_OutputString("lease_time:   %ld\n", dhcp->lease_time);
	LRD_EVT_OutputString("message_type: %d\n",  dhcp->message_type);
	LRD_EVT_OutputString("dns_servers:  %s\n",  dhcp->dns_servers);
	LRD_EVT_OutputString("dhcp_server:  %s\n",  dhcp->dhcp_server);
	LRD_EVT_OutputString("domain_name:  %s\n",  dhcp->domain_name);
	LRD_EVT_OutputString("renew:        %s\n",  dhcp->renew);
	LRD_EVT_OutputString("rebind:       %s\n",  dhcp->rebind);
	LRD_EVT_OutputString("expire:       %s\n",  dhcp->expire);
}

unsigned long long historic_bitmask = 0;

SDCERR event_handler(unsigned long event_type, SDC_EVENT *event)
{
	DHCP_LEASE dhcp;
	historic_bitmask |= (1ull << event_type);

	//reason
	switch (event_type)
	{
		case SDC_E_CONNECT_REQ :
			LRD_EVT_OutputString("Event: %s\t Auth type: %s\n", eventToStr(event_type),
			authModeToStr(event->auth_type));
			break;
		case SDC_E_ROAM :
			LRD_EVT_OutputString("Event: %s\t status: %s\t Roam reason: %s\n", eventToStr(event_type),
			statusToStr(event->status), roamReasonToStr(event->reason));
			break;
		case SDC_E_AUTH :
			LRD_EVT_OutputString("Event: %s\t status: %s\t Auth reason: %s\n", eventToStr(event_type),
			authStatusToStr((LRD_WF_EvtAuthStatus)event->status), authReasonToStr((LRD_WF_EvtAuthReason)event->reason));
			break;
		case SDC_E_DISCONNECT :
		case SDC_E_DISASSOC :
			LRD_EVT_OutputString("Event: %s\t reason: %s\t 80211 reason: %s\n", eventToStr(event_type),
			disconnectReasontoStr((SDC_ATH_DISCONNECT_REASON)event->status), w80211ReasonToStr(event->reason));
			break;
		case SDC_E_DHCP:
			LRD_EVT_OutputString("Event: %s\t status: %s\t reason: %s\n", eventToStr(event_type),
			dhcpStatusToStr((LRD_WF_EvtDHCPStatus)event->status), dhcpReasonToStr((LRD_WF_EvtDHCPReason)event->reason));
			if(outputLease && ((event->status == BOUND) || (event->status == RENEWED) ||
			(event->status == DECONFIG) || (event->status == RELEASED)))
			{
				LRD_WF_GetDHCPLease(&dhcp);
				outputDHCPLease(&dhcp);
			}
			break;
		case SDC_E_CMDERROR:
			LRD_EVT_OutputString("Event: %s\t Error reason: %s\n", eventToStr(event_type),
			cmderrorReasontoStr((SDC_ATH_CMDERROR_REASON)event->reason));
			break;
		case SDC_E_CONNECTION_STATE:
			LRD_EVT_OutputString("Event: %s\t status: %s\n", eventToStr(event_type),
			evtConStatusToStr((LRD_WF_EvtConStatus)event->status));
			if((event->status == AUTHENTICATING) || (event->status == AUTHENTICATED) ||
			   (event->status == AUTH_ERROR)) {
				LRD_EVT_OutputString("\tAuth reason: %s\t\n", authReasonToStr((LRD_WF_EvtAuthReason)event->reason));
			} else if(event->status == ASSOC_ERROR || event->status == NOT_CONNECTED) {
				LRD_EVT_OutputString("\treason: %s\t 80211 reason: %s\n",
				disconnectReasontoStr((SDC_ATH_DISCONNECT_REASON)event->reason), w80211ReasonToStr(event->auth_type));
			}
			break;
		case SDC_E_INTERNAL:
			LRD_EVT_OutputString("Event: %s\t status: %s\t reason: %s\n", eventToStr(event_type),
			intStatusToStr((LRD_WF_EvtIntStatus)event->status),intReasonToStr((LRD_WF_EvtIntReason)event->reason));
			break;
		case SDC_E_FW_ERROR:
			LRD_EVT_OutputString("Event: %s\t reason: %s\n", eventToStr(event_type),
			fwErrReasonToStr((LRD_WF_EvtFwErrorReason)event->reason));
			if (manager) { //only setup for fw_crash recovery if manager active
				if(LRD_WF_SuppDisconnect() != SDCERR_SUCCESS)
					LRD_EVT_OutputString("Failed to stop automatic reconnect after firmware crash\n");
				fw_crash = true;
			}
			break;
		case SDC_E_READY:
			LRD_EVT_OutputString("Event: %s\n", eventToStr(event_type));
			if(fw_crash) {
				if(LRD_WF_SuppReconfigure() != SDCERR_SUCCESS)
					if (LRD_WF_HostAPDRestart() != SDCERR_SUCCESS)
						LRD_EVT_OutputString("Failed to start automatic reconnect after firmware recovery\n");
				fw_crash = false;
			}
			break;
		default:
			LRD_EVT_OutputString("Event: %s\n", eventToStr(event_type));
			break;
	}

	sdc_ether_addr *ea=&event->addr;
	// ether_addr
	if (ea->octet[0] | ea->octet[1] | ea->octet [2] |
			ea->octet[3] | ea->octet[4] | ea->octet [5])
	{
		ether_ntoa(ea, BUFFER);
		LRD_EVT_OutputString("\tAP Mac address: %s\n", BUFFER);
	}

	return(SDCERR_SUCCESS);
}

SDCERR LRD_EVT_ParseTypes(char* string, unsigned long long *eventMask)
{
	char *tok;

	tok = strtok(string, " ,");

	while(tok != NULL)
	{
		unsigned int i;

		for(i = 0; i <= SDC_E_MAX; i++)
		{
			if(strcmp(tok, eventNames[i]) == 0) {
				*eventMask |= ((unsigned long long)1<<i);
				break;
			}
		}

		if(i >= SDC_E_MAX) {
			printf("Invalid type found\n");
			return SDCERR_FAIL;
		}

		tok = strtok(NULL, ",");
	}

	if(*eventMask == 0) {
		printf("No valid types were specified after types option\n");
		return SDCERR_FAIL;
	}

	return SDCERR_SUCCESS;
}



int main(int argc, char *argv[])
{
	unsigned long long eventMask = 0;
	int c, rc;
	bool bitmask_specified = false;

	static struct option long_options[] =
	{
		{"bitmask", required_argument, 0, 'b'},
		{"types", required_argument, 0, 't'},
		{"output", required_argument, 0, 'o'},
		{"lease", no_argument, 0, 'l'},
		{"manager", no_argument, 0, 'm'},
		{0, 0, 0, 0},
	};

	if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
		usage();
		return 0;
	}

	openlog(NULL, LOG_PID|LOG_CONS, LOG_USER);

	signal(SIGINT, sigproc);
	signal(SIGQUIT, sigproc);
	signal(SIGTERM, sigproc);

	while((c = getopt_long(argc, argv, "b:t:o:lm", long_options, NULL)) != -1)
	{
		switch(c)
		{
		case 'b':
			if(bitmask_specified == true) {
				printf("Both bitmask and types arguments cannot be set\n");
				cleanUp();
				return 1;
			}
			eventMask = strtoull(optarg, NULL, 0);
			bitmask_specified = true;
			break;
		case 't':
			if(bitmask_specified == true) {
				printf("Both bitmask and types arguments cannot be set\n");
				cleanUp();
				return 1;
			}
			rc = LRD_EVT_ParseTypes(optarg, &eventMask);
			if(rc != SDCERR_SUCCESS) {
				cleanUp();
				return 1;
			}
			bitmask_specified = true;
			break;
		case 'o':
			if(strcmp("console", optarg) == 0) {
				console = true;
				logging = false;
			} else if(strcmp("logging", optarg) == 0) {
				console = false;
				logging = true;
			} else if(strcmp("both", optarg) == 0) {
				console = true;
				logging = true;
			}
			break;
		case 'l':
			outputLease = true;
			break;
		case 'm':
			manager = true;
			eventMask |= ((unsigned long long)1 << SDC_E_FW_ERROR) | ((unsigned long long)1 << SDC_E_READY);
			break;
		case '?':
			cleanUp();
			return 1;
		default:
			break;
		}
	}

	LRD_EVT_OutputString("Laird Event Monitor Version %s-%u.%u.%u.%u\n", LRD_BLD_NUMBER, LRD_EVENT_MON_VERSION_MAJOR,
	LRD_EVENT_MON_VERSION_MINOR, LRD_EVENT_MON_VERSION_REVISION, LRD_EVENT_MON_VERSION_SUB_REVISION);

	if(eventMask == 0)
		eventMask = 0xFFFFFFFFFFFFFFFF;

	rc = SDCRegisterForEvents(eventMask, event_handler);

	if(rc != SDCERR_SUCCESS) {
		LRD_EVT_OutputString("Failed to Register for Events with rc (%d)\n", rc);
		cleanUp();
		return 1;
	}

	SDCRegisteredEventsList(&eventMask);
	LRD_EVT_OutputString("Current Registered Bitmask 0x%016llX\n", eventMask);

	// sleep forever.  Exit via control-c
	for(;;)
		sleep(1);

	return (0);
}

void usage()
{
	printf("Laird Event Monitor Version %s-%u.%u.%u.%u\n", LRD_BLD_NUMBER, LRD_EVENT_MON_VERSION_MAJOR, LRD_EVENT_MON_VERSION_MINOR, LRD_EVENT_MON_VERSION_REVISION, LRD_EVENT_MON_VERSION_SUB_REVISION);
	printf("Usage: event_mon [OPTIONS]\n");
	printf("\nMonitor Events from the Laird WiFi subsystem\n");
	printf("\nOptions:\n\n");
	printf("    --types,-t	 TYPE,TYPE,..    Specify the Laird event types separated by comma (SDC_E_AUTH,SDC_E_ROAM,...)\n");
	printf("                                 Default is all event types.\n");
	printf("    --bitmask,-b MASK            Specify the event type bitmask directly (0x0000001FA3008000 or 0X0000001FA3008000)\n");
	printf("                                 Only event types OR bitmask can specified.  Default is all event types.\n");
	printf("    --output,-o  console         Outputs events to console (Default)\n");
	printf("                 logging         Outputs events to syslog\n");
	printf("                 both            Outputs to console and syslog\n");
	printf("    --lease,-l                   Output current DHCP lease on BOUND, RENEWED, DECONFIG, and RELEASED\n");
	printf("                                 Default is off\n");
	printf("    --manager,-m                 Enable radio state manager.  This recovers the radio state on a firmware crash.\n");

}

void dumpBitmaskAndExit(unsigned long long historic_mask)
{
	unsigned int i;

	LRD_EVT_OutputString("Laird Event Monitor Exiting\n");
	if(!historic_mask)
	{
		LRD_EVT_OutputString("No events reported\n");
	}
	LRD_EVT_OutputString("Bitmask of events which occurred: 0x%016llX\n", historic_mask);
	LRD_EVT_OutputString("Events:\n");
	for (i=0; i < 8*sizeof(historic_mask); i++)
	{
		if ((1ull<<i) & historic_mask)
			LRD_EVT_OutputString("%s\n",eventToStr(i));
	}
}

void cleanUp()
{
	SDCDeregisterEvents();
	dumpBitmaskAndExit(historic_bitmask);
	closelog();
}

void sigproc(int foo)
{
	cleanUp();
	exit(0);
}
