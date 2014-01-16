/*

Copyright (c) 2013, Laird

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
#include "sdc_sdk.h"

void sigproc(int);

void quitproc(int);

char BUFFER[20] = "                   ";

char * eventToStr(int event)
{
	switch(event)
	{
		case SDC_E_SET_SSID: return "SDC_E_SET_SSID"; break;
		case SDC_E_AUTH: return "SDC_E_AUTH"; break;
		case SDC_E_AUTH_IND: return "SDC_E_AUTH_IND"; break;
		case SDC_E_DEAUTH: return "SDC_E_DEAUTH"; break;
		case SDC_E_DEAUTH_IND: return "SDC_E_DEAUTH_IND"; break;
		case SDC_E_ASSOC: return "SDC_E_ASSOC"; break;
		case SDC_E_ASSOC_IND: return "SDC_E_ASSOC_IND"; break;
		case SDC_E_REASSOC: return "SDC_E_REASSOC"; break;
		case SDC_E_REASSOC_IND: return "SDC_E_REASSOC_IND"; break;
		case SDC_E_DISASSOC: return "SDC_E_DISASSOC"; break;
		case SDC_E_DISASSOC_IND: return "SDC_E_DISASSOC_IND"; break;
		case SDC_E_QUIET_START: return "SDC_E_QUIET_START"; break;
		case SDC_E_QUIET_END: return "SDC_E_QUIET_END"; break;
		case SDC_E_BEACON_RX: return "SDC_E_BEACON_RX"; break;
		case SDC_E_MIC_ERROR: return "SDC_E_MIC_ERROR"; break;
		case SDC_E_ROAM: return "SDC_E_ROAM"; break;
		case SDC_E_PMKID_CACHE: return "SDC_E_PMKID_CACHE"; break;
		case SDC_E_ADDTS_IND: return "SDC_E_ADDTS_IND"; break;
		case SDC_E_DELTS_IND: return "SDC_E_DELTS_IND"; break;
		case SDC_E_ROAM_PREP: return "SDC_E_ROAM_PREP"; break;
		case SDC_E_PSM_WATCHDOG: return "SDC_E_PSM_WATCHDOG"; break;
		case SDC_E_PSK_SUP: return "SDC_E_PSK_SUP"; break;
		case SDC_E_ICV_ERROR: return "SDC_E_ICV_ERROR"; break;
		case SDC_E_RSSI: return "SDC_E_RSSI"; break;
		case SDC_E_DHCP: return "SDC_E_DHCP"; break;
		case SDC_E_READY:  return "SDC_E_READY"; break;
		case SDC_E_CONNECT_REQ:  return "SDC_E_CONNECT_REQ"; break;
		case SDC_E_CONNECT:  return "SDC_E_CONNECT"; break;
		case SDC_E_RECONNECT_REQ:  return "SDC_E_RECONNECT_REQ"; break;
		case SDC_E_DISCONNECT_REQ:  return "SDC_E_DISCONNECT_REQ"; break;
		case SDC_E_DISCONNECT:  return "SDC_E_DISCONNECT"; break;
		case SDC_E_SCAN_REQ:  return "SDC_E_SCAN_REQ"; break;
		case SDC_E_SCAN:  return "SDC_E_SCAN"; break;
		case SDC_E_REGDOMAIN:  return "SDC_E_REGDOMAIN"; break;
		case SDC_E_CMDERROR:  return "SDC_E_CMDERROR"; break;
		case SDC_E_CONNECTION_STATE: return "SDC_E_CONNECTION_STATE"; break;
		case SDC_E_MAX: return "SDC_E_MAX"; break;
		default :
			sprintf(BUFFER, "0x%x", event);
			return BUFFER;
	}
}

/* Event status codes */
char * statusToStr( int status)
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

char * roamReasonToStr( int reason )
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
		default :
			sprintf(BUFFER, "%d", reason);
			return BUFFER;
	}
}

char * w80211ReasonToStr(unsigned int reason)
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

char * disconnectReasontoStr(SDC_ATH_DISCONNECT_REASON reason)
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

char* cmderrorReasontoStr(SDC_ATH_CMDERROR_REASON reason)
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

char* authStatusToStr(LRD_WF_EvtAuthStatus status)
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

char* authReasonToStr(LRD_WF_EvtAuthReason reason)
{
	switch(reason)
	{
	case AUTH_REASON_UNSPEC:   return "AUTH_REASON_UNSPEC"; break;
	case AUTH_SERVER_NO_RESP:  return "AUTH_SERVER_NO_RESP"; break;
	case INVALID_CREDENTIALS:  return "INVALID_CREDENTIALS"; break;
	case METHOD_NOT_SUPPORTED: return "METHOD_NOT_SUPPORTED"; break;
	case INVALID_CERT_PASS:    return "INVALID_CERT_PASS"; break;
	default:
		sprintf(BUFFER, "%d", reason);
		return BUFFER;
	}
}

char* evtConStatusToStr(LRD_WF_EvtConStatus status)
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

char* dhcpStatusToStr(LRD_WF_EvtDHCPStatus status)
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

char* dhcpReasonToStr(LRD_WF_EvtDHCPReason reason)
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

char* authModeToStr( int auth_type )
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

char *ether_ntoa(const sdc_ether_addr *ea, char *buf)
{
	static const char template[] = "%02x:%02x:%02x:%02x:%02x:%02x";
	snprintf(buf, 18, template,
			 ea->octet[0]&0xff, ea->octet[1]&0xff, ea->octet[2]&0xff,
			 ea->octet[3]&0xff, ea->octet[4]&0xff, ea->octet[5]&0xff);
	return (buf);
}

void printDHCPLease(const DHCP_LEASE *dhcp)
{
	printf("interface:    %s\n",  dhcp->interface);
	printf("address:      %s\n",  dhcp->address);
	printf("subnet_mask:  %s\n",  dhcp->subnet_mask);
	printf("routers:      %s\n",  dhcp->routers);
	printf("lease_time:   %ld\n", dhcp->lease_time);
	printf("message_type: %d\n",  dhcp->message_type);
	printf("dns_servers:  %s\n",  dhcp->dns_servers);
	printf("dhcp_server:  %s\n",  dhcp->dhcp_server);
	printf("domain_name:  %s\n",  dhcp->domain_name);
	printf("renew:        %s\n",  dhcp->renew);
	printf("rebind:       %s\n",  dhcp->rebind);
	printf("expire:       %s\n",  dhcp->expire);
}

unsigned long long historic_bitmask = 0;

SDCERR event_handler(unsigned long event_type, SDC_EVENT *event)
{
	DHCP_LEASE dhcp;
	historic_bitmask |= (1ull << event_type);

	printf("event: %s", eventToStr(event_type));
	//reason
	switch (event_type)
	{
		case SDC_E_CONNECT_REQ :
			printf("\tAuth type: %s\n", authModeToStr(event->auth_type));
			break;
		case SDC_E_ROAM :
			printf("\tstatus: %s", statusToStr(event->status));
			if(event->reason)
				printf("\tRoam reason: %s", roamReasonToStr(event->reason));
			break;
		case SDC_E_AUTH :
			printf("\tstatus: %s", authStatusToStr(event->status));
			if(event->reason)
				printf("\tAuth reason: %s", authReasonToStr(event->reason));
			break;
		case SDC_E_DISCONNECT :
		case SDC_E_DISASSOC :
			printf("\tstatus/reason: %s", disconnectReasontoStr(event->status));
			if(event->reason)
				printf("\t80211 reason: %s", w80211ReasonToStr(event->reason));
			break;
		case SDC_E_DHCP:
			printf("\tstatus: %s", dhcpStatusToStr(event->status));
			if(event->reason)
				printf("\tDHCP reason: %s", dhcpReasonToStr(event->reason));
			if((event->status == BOUND) || (event->status == RENEWED) ||
			   (event->status == DECONFIG) || (event->status == RELEASED))
			{
				printf("\n");
				LRD_WF_GetDHCPLease(&dhcp);
				printDHCPLease(&dhcp);
			}
			break;
		case SDC_E_CMDERROR:
			if(event->reason)
				printf("\tError reason: %s", cmderrorReasontoStr(event->reason));
			break;
		case SDC_E_CONNECTION_STATE:
			printf("\tstatus: %s", evtConStatusToStr(event->status));
			if((event->status == AUTHENTICATING) || (event->status == AUTHENTICATED) ||
			   (event->status == AUTH_ERROR))
				printf("\tAuth reason: %s", authReasonToStr(event->reason));
			else
				printf("\treason: %s", disconnectReasontoStr(event->reason));
			printf("\t80211 reason: %s", w80211ReasonToStr(event->auth_type));
			break;
	}

	printf("\n");

	sdc_ether_addr *ea=&event->addr;
	// ether_addr
	if (ea->octet[0] | ea->octet[1] | ea->octet [2] |
			ea->octet[3] | ea->octet[4] | ea->octet [5])
	{
		ether_ntoa(ea, BUFFER);
		printf("\taddress: %s\n", BUFFER);
	}

	printf("\n");
	return(SDCERR_SUCCESS);
}

int main()
{
	unsigned long long event_mask =0;
	int i, rc;

	signal(SIGINT, sigproc);
	signal(SIGQUIT, quitproc);

	for (i=(int)SDC_E_SET_SSID; i< SDC_E_MAX; i++)
	{
		event_mask |= (1<<i);
	}

	event_mask =	0xFFFFFFFFFFFFFFFF;
	//(1ULL << SDC_E_ASSOC)          |
	//(1ULL << SDC_E_AUTH)           |
	//(1ULL << SDC_E_DISASSOC)       |
	//(1ULL << SDC_E_DHCP)           |
	//(1ULL << SDC_E_READY)          |
	//(1ULL << SDC_E_CONNECT_REQ)    |
	//(1ULL << SDC_E_CONNECT)        |
	//(1ULL << SDC_E_RECONNECT_REQ)  |
	//(1ULL << SDC_E_DISCONNECT_REQ) |
	//(1ULL << SDC_E_DISCONNECT)     |
	//(1ULL << SDC_E_SCAN_REQ)       |
	//(1ULL << SDC_E_SCAN)           |
	//(1ULL << SDC_E_REGDOMAIN)      |
	//(1ULL << SDC_E_CMDERROR);

	rc = SDCRegisterForEvents( event_mask, event_handler);

	printf("RegisterForEvents rc 0x%x\n", rc);
	printf("Registered Bitmask 0x%016llX\n", event_mask);

	SDCRegisteredEventsList(&event_mask);
	printf("Registered Bitmask 0x%016llX\n", event_mask);

	// sleep forever.  Exit via control-c
	for(;;)
		sleep(1);

	return (0);
}

void dumpBitmaskAndExit(unsigned long long historic_mask)
{
	int i;
	if(!historic_mask)
	{
		printf("\nNo events reported\n");
	}
	printf("\nBitmask of events which occured: 0x%016llX\n", historic_mask);
	printf("Events:\n");
	for (i=0; i < 8*sizeof(historic_mask); i++)
	{
		if ((1ull<<i) & historic_mask)
					printf("%s\n",eventToStr(i));
	}
}

void sigproc(int foo)
{
	SDCDeregisterEvents();
	dumpBitmaskAndExit(historic_bitmask);
	exit(0);
}

void quitproc(int foo)
{
	SDCDeregisterEvents();
	dumpBitmaskAndExit(historic_bitmask);
	exit(0);
}
