package com.aex.common.servlet;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import com.aex.common.bdo.DataAccessException;
import com.aex.common.bdo.UnknownTradingPartnerException;
import com.aex.common.bdo.UserBDO;
import com.aex.common.data.User;
import com.aex.common.exception.AEXException;
import com.aex.common.manager.ConnectionPoolManager;
import com.aex.common.manager.LoggerManager;
import com.aex.common.manager.PropertyManager;
import com.aex.common.manager.PropertySet;

/**
 * Ensures that the user is logged in, directs them to Exchange if they aren't, saves
 * and restores parameters as necessary.<br/>
 * 
 * If the user is logged in (the user object exists in "aex.common.user" in the session),
 * the servlet is sent to the next filter.  If the user is not logged in, any parameters are saved
 * and the user is sent to Exchange.  If the user is coming from exchange to login (has an
 * action with the value REDIRECTION), then the parameters that were saved before are
 * restored or they are taken from what Exchange is passing if they weren't saved before
 * and the servlet is sent to the next filter.<br/>
 * 
 * Generally one of two sequences will happen.  The first is that the user will try to hit a page in Tomcat
 * and this filter will determine that the user isn't logged in.  In that case, the following steps are hit:
 * <ol>
 * <li>Save the parameters</li>
 * <li>Send them to Exchange</li>
 * <li>Exchange logs them in</li>
 * <li>Exchange saves the login info to the database</li>
 * <li>Exchange sends them back here with the action REDIRECTION</li>
 * <li>Their login info is read and a user object created</li>
 * <li>They are redirected to Tomcat with their original action</li>
 * <li>The login filter is hit and sees that there are saved param and restores them</li>
 * <li>The next filter in the chain is invoked</li>
 * </ol>
 * The second is that the user comes to Tomcat from Exchange.  In this case, the following steps
 * are hit:
 * <ol>
 * <li>Exchange saves the login info to the database</li>
 * <li>Exchange sends them back here with the action REDIRECTION</li>
 * <li>Their login info is read and a user object created and the parameters are saved</li>
 * <li>They are redirected to Tomcat with their original action</li>
 * <li>The login filter is hit and sees that there are saved param and restores them</li>
 * <li>The next filter in the chain is invoked</li>
 * </ol>
 */
public class LoginFilter implements Filter {
	private Logger log;
	public static final String HEADER_ID="$Header: /apps/cvs/cvsroot/aex/common/src/java/com/aex/common/servlet/LoginFilter.java,v 1.65 2012/09/07 18:11:35 sparuchuri Exp $";

	/**
	 * Ensures that the user is logged in.  If they aren't logged in, it saves their parameters
	 * and redirects them to the login page.  If they logging in from Exchange, get their parameters
	 * and put them back into the request.
	 * 
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)
	 */
    protected boolean isUserLoggedIn(HttpSession session, String oexId) {
        User user = (User) session.getAttribute("aex.common.user");
        return user != null && oexId != null && oexId.equals(user.getOexSessionId());
    }

	/**
	 * Stores the parameters in the session for later retrieval.
	 * 
	 * @param session The session to store the parameters in.
	 * @param paramMap The map of parameters to save.
	 */
	public static void saveRedirectionParameters(HttpSession session, Map paramMap) {
		Map oldParams = (Map)session.getAttribute("REDIRECTION_PARAMETERS");
		if (oldParams != null) {
			// Add parameters to current map - don't replace since there may be existing ones saved
			// before redirecting to exchange.
			paramMap.putAll(oldParams); // Overwrite params from exchange with saved params
		}
		session.setAttribute("REDIRECTION_PARAMETERS", paramMap);
	}

	/**
	 * This method logs the user in by retrieving the data from the database using the specified
	 * authorization id.
	 * 
	 * @param authId the authorization id to retrieve data from the database with (inserted by Exchange)
	 * @param session HttpSession object associated with this request.
	 * @param conn the LBTS connection
	 * @return boolean returns true if the user is logged in.
	 */
    @Deprecated
	private boolean loginUser(int authId, String oexId, HttpSession session, Connection coreConn,Connection appsConn) throws UnknownTradingPartnerException {
		boolean loggedIn = false;
		UserBDO userBDO = new UserBDO(appsConn,coreConn, null);
		User user;
		try {
			user = userBDO.loadUser(authId);
		} catch (DataAccessException e) {
			LoggerManager.getLogger(getClass()).error("Error loading user", e);
			return false;
		}
		if (user != null) {
            user.setOexSessionId(oexId);
			session.setAttribute("aex.common.user", user);
			loggedIn = true;
		}
		userBDO.deleteTomcatMigratedUsers(authId);
		
		return loggedIn;
	}
    private boolean loginUser(HttpSession session, Connection coreConn,Connection appsConn, String username, String oexSessionId, int oexTpId) {
        boolean loggedIn = false;
        UserBDO userBDO = new UserBDO(appsConn,coreConn, null);
        User user;
        
        try {
        	User usr = (User)session.getAttribute("aex.common.user");
        	if(usr != null)
        		user = usr;
        	else
        		user = userBDO.loadUser(username, oexTpId);
        } catch (DataAccessException e) {
            LoggerManager.getLogger(getClass()).error("Error loading user", e);
            return false;
        }
        if (user != null) {
            user.setOexSessionId(oexSessionId);
            session.setAttribute("aex.common.user", user);
            loggedIn = true;
        }
        return loggedIn;
    }
	public static Map getRedirectionParameters(HttpSession session) {
		if (session != null) {
			return (Map) session.getAttribute("REDIRECTION_PARAMETERS");
		}
		return null;
	}

	/**
	 * Returns the machine name based on the properties (http://machine:port)
	 * 
	 * @return
	 */
	public static String getMachineName() {
		PropertySet props = PropertyManager.getProperties();
		String machineHost = props.get("MACHINE_HOST");
		String machinePort = props.get("MACHINE_PORT");
		String machineProtocol = props.get("MACHINE_PROTOCOL");
		String machineName = machineProtocol + "://" + machineHost;
		if (!"".equals(machinePort)) {
			machineName += ":" + machinePort;
		}
		return machineName;
	}
    
    /**
     * Same as getMachineName but returns localhost as the host always. 
     * Needed because preview cannot resolve its own machineName due to natting
     */
    public static String getLocalMachineName() {
        PropertySet props = PropertyManager.getProperties();
        String machineHost = "localhost";
        String machinePort = props.get("MACHINE_PORT");
        String machineProtocol = props.get("MACHINE_PROTOCOL");
        String machineName = machineProtocol + "://" + machineHost;
        if (!"".equals(machinePort)) {
            machineName += ":" + machinePort;
        }
        return machineName;
    }

	/**
	 * Returns true if this is a login redirection from Exchange.  The user is logged in and
	 * redirected to Tomcat (to hide the auth id from the url).  If it's a login redirection,
	 * the parameters are loaded from the database and saved in the session so that they
	 * are used when invoked from the redirection.
	 * 
	 * @param request
	 * @param response
	 * @return
	 * @throws SQLException
	 * @throws IOException
	 */
	protected boolean handledAsRedirection(
		HttpServletRequest request,
		HttpServletResponse response, String oexId)
		throws SQLException, IOException {

		String action = request.getParameter("Action");
		if ((action != null) && (action.equals("REDIRECTION"))) {
			// Redirecting - load parameter map
			Connection coreConn = null;
			Connection appsConn = null;
			boolean connFromPool = false;
			try {
				HttpSession session = request.getSession(true);
				appsConn = ConnectionPoolManager.getPooledConnection();
				coreConn = (Connection) request.getAttribute(ConnectionFilter.AEX_CORE_CONNECTION_NAME);
				if (coreConn == null) {
					coreConn = ConnectionPoolManager.getAexCorePooledConnection();
					connFromPool = true;
				}
				int authorizationId = Integer.parseInt(request.getParameter("authorizationId"));
				try {
					loginUser(authorizationId, oexId, session, coreConn,appsConn);
				} catch (UnknownTradingPartnerException e) {
					AEXException ex = new AEXException(e);
					ex.setUserFriendlyMessage("Your trading partner is not in Aeroxchange.  Please contact Aeroxchange to get access.");
					throw ex;
				}
				
				Map parameterMap = new HashMap();
				User user = (User)session.getAttribute("aex.common.user");
				String ssoUserId = request.getParameter("ssoUserId");
				String ssoUserRole = request.getParameter("ssoUserRole");
				String ssoCompanyId = request.getParameter("ssoCompanyId");
				session.setAttribute("common.sso.userId", ssoUserId);
				session.setAttribute("common.sso.userRole", ssoUserRole);
				session.setAttribute("common.sso.userOriginalRole", ssoUserRole);
				session.setAttribute("common.sso.companyId", ssoCompanyId);
				
				UserBDO userBDO = new UserBDO(appsConn,coreConn, user);
				parameterMap = userBDO.findOexRedirectionParameters(authorizationId);
				//userBDO.deleteTomcatMigratedUsers(authorizationId);

				if (parameterMap == null) {
					log.error("No redirection parameter map");
					throw new AEXException("No redirection parameter map");
				}
				saveRedirectionParameters(session, parameterMap);
				// Get the parameters in case there were parameters saved from a redirect to exchange
				parameterMap = getRedirectionParameters(session);
				action = (String) parameterMap.get("Action");
				
				// get the workflow Type
				String workflowType = (String) parameterMap.get("WorkFlowType");				
				String responsePath = getMachineName() + request.getContextPath() + "/" + action;
				
				if (workflowType != null || !"".equals(workflowType))
					responsePath=responsePath.concat("?WorkflowType="+workflowType);
				
				response.sendRedirect(responsePath);
			} finally {
				if (appsConn != null) {
					try {
						appsConn.commit();
						if (connFromPool) {
							ConnectionPoolManager.releasePooledConnection(appsConn);
						}
					} catch (SQLException e) {
					}
				}
				if (coreConn != null) {
					try {
						coreConn.commit();
						if (connFromPool) {
							ConnectionPoolManager.releasePooledConnection(coreConn);
						}
					} catch (SQLException e) {
					}
				}
			}
			return true;
		}
		return false;
	}

	/**
	 * Returns <code>true</code> if this web hit was handled as a redirection to Exchange
	 * for login.  If true, no other action should be taken.  If handled as a redirection, any parameters
	 * are saved in the session for later restoration.

	 * @param request
	 * @param response
	 * @return
	 * @throws IOException
	 */
	protected boolean handledAsLoginRedirect(
		HttpServletRequest request,
		HttpServletResponse response, String oexId)
		throws IOException {
        
		HttpSession session = request.getSession(true);
		if (!isUserLoggedIn(session, oexId)) {
			// Store all parameters in redirection map
			Map params = new HashMap();
			for (Enumeration e = request.getParameterNames();
				e.hasMoreElements();
				) {
				String name = (String) e.nextElement();
				String[] values = request.getParameterValues(name);
				if (values.length == 1) {
					params.put(name, values[0]);
				} else {
					params.put(name, values);
				}
			}
			if (!params.containsKey("Action")) {
				// Save the servlet path as the action
				String action = request.getServletPath();
				if (action.startsWith("/")) {
					action = action.substring(1);
				}
				params.put("Action", action);
			}
			saveRedirectionParameters(session, params);
			// Send back to OEXServlet as a redirect
			response.sendRedirect(getMachineName() + "/aexportal/AEXServlet?Action=REDIRECTION_LOGIN&app=" + session.getServletContext().getServletContextName());
			return true;
		}
		return false;
	}
    
	public String convertStreamToString(InputStream is) throws IOException { 
		/* To convert the InputStream to String we use the BufferedReader.readLine() 
		   method. We iterate until the BufferedReader return null which means 
		   there's no more data to read. Each line will appended to a StringBuilder 
		   and returned as String. 
		 */
		if (is != null) { 
			StringBuilder sb = new StringBuilder(); 
			String line; 
			try { 
			BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8")); 
				while ((line = reader.readLine()) != null) { 
					sb.append(line).append("\n"); 
				} 
			} 
			finally { 
				is.close(); 
			} 
			return sb.toString(); 
		} 
		else {         
			return ""; 
			} 
	} 

    protected boolean getUserFromOex (
            HttpServletRequest request,
            HttpServletResponse response, String oexId)
            throws IOException {

            HttpSession session = request.getSession(true);
    		PropertySet props = PropertyManager.getProperties();
    		String machineHost = props.get("MACHINE_HOST");
    		HttpMethod method = null;
    		 HttpClient client = null;
    		 String loginName = null;
    		try{
    		    client = getHttpClient(machineHost, oexId);
                method = new GetMethod(getMachineName() + "/aexportal/AEXServlet?getLoginName=true");
                client.executeMethod(method);
            	loginName = method.getResponseBodyAsString();
            	if(loginName==null ||  "".equals(loginName.trim())){
            		session.removeAttribute("aex.common.user");
            		oexId=null;
            	}else{
                	Map<String,String> lAexServletResponse = this.parseAexServletResponse(loginName);
                	String loginUserName = lAexServletResponse.get( "LoginName" );
                	String lAexTpId = lAexServletResponse.get( "AexTpId" );
                	User user =(User) session.getAttribute("aex.common.user");
                	if( user!=null ) {
                		if ( !loginUserName.equalsIgnoreCase(user.getLoginName() ) )
                				session.removeAttribute("aex.common.user");
                		if ( loginUserName.equalsIgnoreCase(user.getLoginName() ) && !lAexTpId.equalsIgnoreCase( "" + user.getTradingPartner().getTpId() ) )
                			session.removeAttribute("aex.common.user");
                	}
                		
            	}
    		    }
    		    finally{
    		        if (method != null)
    		            method.releaseConnection();
    		    }
    		    
            if (!isUserLoggedIn(session, oexId)) {
                client = getHttpClient(machineHost, oexId);
                method = new GetMethod(getMachineName() + "/aexportal/AEXServlet?getLoginName=true");

                Connection appsConn = null;
                Connection coreConn = null;
                boolean connFromPool = false;
                boolean appsConnFromPool = false;
                try{
                    log.debug("Attempting to retrieve login name from oex...");
                    method.setQueryString("getLoginName=true");
                    client.executeMethod(method);
                    
                    loginName = new String(method.getResponseBody(), "UTF-8");
                    int lAexTpId = 0;
                    int lOexTpId = 0;
                    //String loginName = convertStreamToString(method.getResponseBodyAsStream());
                    if (StringUtils.isBlank(loginName)) {
                        log.debug("User is not logged into exchange");
                        return false;
                    } else {
                    	Map<String,String> lAexServletResponse = this.parseAexServletResponse( new String( method.getResponseBody(), "UTF-8") );
                    	loginName = lAexServletResponse.get( "LoginName" );
                    	lAexTpId = Integer.parseInt( lAexServletResponse.get( "AexTpId" ) );
                    	lOexTpId = Integer.parseInt( lAexServletResponse.get( "OexTpId" ) );
                    	log.debug("Login name retrieved from oex: " + loginName);
                    	log.debug("AexTpId retrieved from oex: " + lAexTpId);
                    	log.debug("OexTpId retrieved from oex: " + lOexTpId);
                    } 
                    
                    appsConn = (Connection) request.getAttribute(ConnectionFilter.AEX_CONNECTION_NAME);
    				if (appsConn == null) {
    					appsConn = ConnectionPoolManager.getPooledConnection();
    					appsConnFromPool = true;
    				}
                    
                    coreConn = (Connection) request.getAttribute(ConnectionFilter.AEX_CORE_CONNECTION_NAME);
                    if (coreConn == null) {
                    	coreConn = ConnectionPoolManager.getAexCorePooledConnection();
                        connFromPool = true;
                    }
                    try {
                        boolean userLogged = loginUser(session, coreConn,appsConn, loginName, oexId, lOexTpId);
                        
                        if(userLogged){
                        	User user = (User) request.getSession().getAttribute("aex.common.user");
                        	if(user.hasPermission("AEX_FHSPI_OPERATOR")){
                        		request.getSession().setAttribute("common.sso.userId", "sso_operator");
                        		request.getSession().setAttribute("common.sso.userRole", "operator");
                        		request.getSession().setAttribute("common.sso.userOriginalRole", "operator");
                        	}
                        	else if(user.hasPermission("AEX_FHSPI_SSO_USER")){
                        		if (!retrieveSSOUserInfo(client, request))
                        			userLogged = false;
                        	}
                        }
                        
                        return userLogged;
                    	
                    } catch (UnknownTradingPartnerException e) {
                        AEXException ex = new AEXException(e);
                        ex.setUserFriendlyMessage("Your trading partner is not in Aeroxchange.  Please contact Aeroxchange to get access.");
                        throw ex;
                    }
                } finally {
                    method.releaseConnection();
                    if (appsConn != null) {
                        try {
                        	appsConn.commit();
                            if (appsConnFromPool) {
                                ConnectionPoolManager.releasePooledConnection(appsConn);
                            }
                        } catch (SQLException e) {
                        }
                    }
                    if (coreConn != null) {
                        try {
                            coreConn.commit();
                            if (connFromPool) {
                                ConnectionPoolManager.releasePooledConnection(coreConn);
                            }
                        } catch (SQLException e) {
                        }
                    }

                }
            }
//            if (isSSOUser(request)) {
//           		retrieveSSOUserInfo(getHttpClient(machineHost, oexId), request);
//            	return true;
//            } else {
//            	return false;
//            }
            return false;
        }

    
    
    private HttpClient getHttpClient(String machineHost, String oexId) {
    	 org.apache.commons.httpclient.Cookie c = new org.apache.commons.httpclient.Cookie(
         		machineHost, "JSESSIONID", oexId);
         c.setPath("/");
         HttpClient client = new HttpClient();
         client.getState().addCookie(c);
         return client;
    }
    private boolean retrieveSSOUserInfo(HttpClient client, HttpServletRequest  request) {
        HttpMethod ssoUserMethod = new GetMethod(getMachineName() + "/aexportal/AEXServlet?getSSOLoginId=true");
        HttpMethod ssoRoleMethod = new GetMethod(getMachineName() + "/aexportal/AEXServlet?getSSOLoginRole=true");
        HttpMethod ssoCompanyMethod = new GetMethod(getMachineName() + "/aexportal/AEXServlet?getSSOCompanyId=true");
        Connection conn = null;
        boolean connFromPool = false;
        try {
        	//for sso
        	ssoUserMethod.setQueryString("getSSOLoginId=true");
        	client.executeMethod(ssoUserMethod);
        	String ssoUserId = ssoUserMethod.getResponseBodyAsString();
        	if (ssoUserId != null && !ssoUserId.trim().equals("")) {//Internal server error response > 50 characters.
        		if (ssoUserId.trim().length() < 50) {// AEX_SSO_USER.USER_ID column length is 50 bytes.
        			log.debug("SSO login id retrieved from oex: " + ssoUserId);
        			request.getSession().setAttribute("common.sso.userId", ssoUserId);
        		} else {
        			return false;
        		}
        	}
        	ssoRoleMethod.setQueryString("getSSOLoginRole=true");
        	client.executeMethod(ssoRoleMethod);
        	String ssoUserRole =  ssoRoleMethod.getResponseBodyAsString();
        	if (ssoUserRole != null && !ssoUserRole.trim().equals("")) {
        		if (ssoUserRole.trim().length() < 50) {// AEX_ROLES.ROLE_NAME column length is 50 bytes.
	        		log.debug("SSO login role retrieved from oex: " + ssoUserRole);
        			request.getSession().setAttribute("common.sso.userRole", ssoUserRole);
	        		request.getSession().setAttribute("common.sso.userOriginalRole", ssoUserRole);
        		} else {
        			return false;
        		}
        	}
        	
        	ssoCompanyMethod.setQueryString("getSSOCompanyId=true");
        	client.executeMethod(ssoCompanyMethod);
        	String ssoCompanyId =  ssoCompanyMethod.getResponseBodyAsString();
        	if (ssoCompanyId != null && !ssoCompanyId.trim().equals("")) {
        		if (ssoCompanyId.trim().length() < 50) {// AEX_SSO_USER.COMPANY_ID column length is 50 bytes.
        			log.debug("SSO Company Id retrieved from oex: " + ssoCompanyId);
        			request.getSession().setAttribute("common.sso.companyId", ssoCompanyId);
        		} else {
        			return false;
        		}
        	}
        	return true;
        	//end sso
        }catch(Exception e){
        	e.printStackTrace();
        	log.error("Error retrieving SSO Info " + e.getMessage());
        	return false;
        }
        finally{
            if (ssoUserMethod != null)
                ssoUserMethod.releaseConnection();
            if (ssoRoleMethod != null)                
                ssoRoleMethod.releaseConnection();
            if (ssoCompanyMethod != null)                                
                ssoCompanyMethod.releaseConnection();
        }
    }


    
    private boolean isSSOUser(HttpServletRequest request) {
    	User user = (User) request.getSession().getAttribute("aex.common.user");
        return (user.getUserName().equalsIgnoreCase("airbus_sso") ||user.getUserName().equalsIgnoreCase("sso_operator")) ; 
    }
	/* (non-Javadoc)
	 * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
	 */
	public void init(FilterConfig config) throws ServletException {
		log = Logger.getLogger(this.getClass());
	}

	/* (non-Javadoc)
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)
	 */
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

		log.debug("Entering login filter do filter ..... ");
		//delegate the request to the appropriate request handler
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		HttpSession session = httpRequest.getSession();
        
        String oexId = null;
        if (httpRequest.getCookies() != null) {
            for (Cookie c : httpRequest.getCookies()) {
                oexId = c.getName().equals("JServSessionIdoex") ? c.getValue() : oexId;
            }
        }
        if (oexId == null) {
            log.debug("User not logged into Exchange.");
        }

		try {
			if (oexId != null && handledAsRedirection(httpRequest, httpResponse, oexId)) {
				// This is a redirection from Exchange - handled in method
				return;
			}
		} catch (SQLException e) {
			throw new ServletException(e);
		} catch (IOException e) {
			throw new ServletException(e);
		}
        if (oexId != null && getUserFromOex(httpRequest, httpResponse, oexId)) {
            log.debug("Successfully retrieve user object based on oex login id.");
        } else if (isFHSAppRequest(session)) {
        	if (isSSOLoggedOut(httpRequest, httpResponse, oexId)) {
        		return;
        	}
		} else if (handledAsLoginRedirect(httpRequest, httpResponse, oexId)) {
			// Login required - handled in method
			return;
		}
			
		Map params = getRedirectionParameters(session);
		try {
			if (params != null) {
				session.removeAttribute("REDIRECTION_PARAMETERS");
				chain.doFilter(new RequestWrapper((HttpServletRequest) request, params), response);
			} else {
				//log.debug("Enter Redirection params null ....");
				chain.doFilter(request, response);
				//log.debug("Exit Redirection params null ....");
			}
		} catch (UnknownTradingPartnerException e) {
			AEXException ex = new AEXException(e);
			ex.setUserFriendlyMessage("Your trading partner is not setup for this application.  Please contact Aeroxchange to get access.");
			throw ex;
		}
	}

	/* (non-Javadoc)
	 * @see javax.servlet.Filter#destroy()
	 */
	public void destroy() {
	}
	
	private boolean isFHSAppRequest(HttpSession session) {
		return session.getServletContext().getServletContextName().toLowerCase().startsWith("fhs");
	}
	
	private boolean isSSOLoggedOut(HttpServletRequest request, HttpServletResponse response, String oexId) throws IOException{
	    
		HttpSession session = request.getSession();

		//jpdebug.begin
		/*
	    session.setAttribute("common.sso.userId","SSO_OPERATOR");
	    //session.setAttribute("common.sso.userRole","FHS_AIB_ADMIN");
	    session.setAttribute("common.sso.userRole","FHS_CUS_ORDER_ADMIN");
	    session.setAttribute("common.sso.companyId","D4296");
	    oexId="523672727111AFA4E23D3C6AE1C30401";
	    Connection appsConn = (Connection) request.getAttribute(ConnectionFilter.AEX_CONNECTION_NAME);
        if (appsConn == null) {
            appsConn = ConnectionPoolManager.getPooledConnection();
            
            //appsConnFromPool = true;
        }
	    loginUser(session,(Connection) request.getAttribute(ConnectionFilter.AEX_CORE_CONNECTION_NAME), 
	                 appsConn,"SSO_OPERATOR", oexId, 0);
		*/
	    //jpdebug.end

	        
		if (session != null) {
			String ssoUserId = (String)session.getAttribute("common.sso.userId");
			String ssoUserRole = (String)session.getAttribute("common.sso.userRole");
			String ssoCompanyId = (String)session.getAttribute("common.sso.companyId");
			if (!isUserLoggedIn(session, oexId)|| StringUtils.isEmpty(ssoUserId) || StringUtils.isEmpty(ssoUserRole) || StringUtils.isEmpty(ssoCompanyId)) {
				log.debug("Session is logged out or timed out in FHS for " + oexId);
				PropertySet props = PropertyManager.getProperties();
				String returnURL = props.get("RETURN_URL");
				String status = "201";
				response.sendRedirect(returnURL + status);
				//response.sendRedirect(getMachineName() + "/" + session.getServletContext().getServletContextName().toLowerCase() + "/logout");
				return true;
			} else {
				return false;
			}
		} else {
			return true;
		}
	}
	
	/**
	 * 
	 * @param pResponse
	 * @return
	 */
	private Map<String,String> parseAexServletResponse( String pResponse ){
		Map<String,String> lAexServletResponse = null;
		if ( pResponse != null && !"".equals( pResponse ) ) {
			try {
				DocumentBuilderFactory lDocumentBuilderFactory = DocumentBuilderFactory.newInstance();
				DocumentBuilder lDocumentBuilder = lDocumentBuilderFactory.newDocumentBuilder();
				Document lDocument = lDocumentBuilder.parse( new ByteArrayInputStream( pResponse.getBytes() ) );
				XPathFactory lXPathFactory = XPathFactory.newInstance();
			    XPath lXPath = lXPathFactory.newXPath();
			    String lLoginName = ( String ) lXPath.evaluate( "/AexServlet/LoginName", lDocument, XPathConstants.STRING );
			    String lAexTpId = ( String ) lXPath.evaluate( "/AexServlet/AexTpId", lDocument, XPathConstants.STRING );
			    String lOexTpId = ( String ) lXPath.evaluate( "/AexServlet/OexTpId", lDocument, XPathConstants.STRING );
			    lAexServletResponse = new HashMap<String,String>();
			    lAexServletResponse.put( "LoginName", lLoginName );
			    lAexServletResponse.put( "AexTpId", lAexTpId );
			    lAexServletResponse.put( "OexTpId", lOexTpId );
			} catch( ParserConfigurationException exParserConfiguration ) {
				exParserConfiguration.printStackTrace();
			} catch( SAXException exSAX ) {
				exSAX.printStackTrace();
			} catch( IOException exIO ) {
				exIO.printStackTrace();
			} catch ( XPathExpressionException exXPathExpression ) {
				exXPathExpression.printStackTrace();
			}
		}
		return lAexServletResponse;
	}
	
}
