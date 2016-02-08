/*******************************************************************************
 * Copyright 2015 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.unison.proxy.auth.twitter;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.http.HttpHeaders;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;

import com.google.common.base.Charsets;
import com.google.common.base.Joiner;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AuthMechanism;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.twitter.hbc.core.HttpConstants;
import com.twitter.hbc.httpclient.auth.Authentication;
import com.twitter.hbc.httpclient.auth.OAuth1;
import com.twitter.joauth.Normalizer;
import com.twitter.joauth.OAuthParams;
import com.twitter.joauth.Request.Pair;
import com.twitter.joauth.Signer;
import com.twitter.joauth.UrlCodec;

public class TwitterAuth implements AuthMechanism {

	SecureRandom secureRandom;
	static Logger logger = Logger.getLogger(TwitterAuth.class.getName());
	
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		
		secureRandom = new SecureRandom();

	}

	public String getFinalURL(HttpServletRequest request, HttpServletResponse response) {
		// TODO Auto-generated method stub
		return null;
	}

	public void doGet(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		
		HttpSession session = ((HttpServletRequest) request).getSession();
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		
		MyVDConnection myvd = cfg.getMyVD();
		
		String consumerKey = authParams.get("consumerKey").getValues().get(0);
		String consumerSecret = authParams.get("consumerSecret").getValues().get(0);
		String accessToken = authParams.get("accessToken").getValues().get(0);
		String accessSecret = authParams.get("accessSecret").getValues().get(0);
		
		boolean linkToDirectory = Boolean.parseBoolean(authParams.get("linkToDirectory").getValues().get(0));
		String noMatchOU = authParams.get("noMatchOU").getValues().get(0);
		String uidAttr = authParams.get("uidAttr").getValues().get(0);
		String lookupFilter = authParams.get("lookupFilter").getValues().get(0);
		//String userLookupClassName = authParams.get("userLookupClassName").getValues().get(0);
		
		
		
		
		
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		
		
		
		
		
		URL reqURL = new URL(request.getRequestURL().toString());
		String redirectURL = reqURL.getProtocol() + "://" + reqURL.getHost();
		if (reqURL.getPort() != -1) {
			redirectURL += ":" + reqURL.getPort();
		}
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
		
		
		
		
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		String authMechName = amt.getName();
		redirectURL += cfg.getAuthMechs().get(authMechName).getUri();
		
		if (request.getParameter("oauth_verifier") == null) {
		
			BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(GlobalEntries.getGlobalEntries().getConfigManager().getHttpClientSocketRegistry());
			RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build();
			CloseableHttpClient http = HttpClients.custom().setConnectionManager(bhcm).setDefaultRequestConfig(rc).build();
			
			HttpPost post = new HttpPost("https://api.twitter.com/oauth/request_token");
			
			this.signRequest(post, "", accessToken, accessSecret, consumerKey, consumerSecret);
			
			CloseableHttpResponse httpResp = http.execute(post);
			
			BufferedReader in = new BufferedReader(new InputStreamReader(httpResp.getEntity().getContent()));
			
			StringBuffer token = new StringBuffer();
			
			
			String line = null;
			while ((line = in.readLine()) != null) {
				token.append(line);
			}
			
			
			
			httpResp.close();
			bhcm.close();
			
			System.err.println(token);
			
			List<NameValuePair> parsed = URLEncodedUtils.parse(token.toString(), Charsets.UTF_8);
			HashMap<String,String> accessTokens = new HashMap<String,String>();
			
			for (NameValuePair nvp : parsed) {
				accessTokens.put(nvp.getName(), nvp.getValue());
			}
			
			request.getSession().setAttribute("twitterAccessToken", accessTokens);
			
			StringBuffer b = new StringBuffer().append("https://api.twitter.com/oauth/authenticate?oauth_token=").append(accessTokens.get("oauth_token"));
			response.sendRedirect(b.toString());
		} else {
			String oauthVerifier = request.getParameter("oauth_verifier");
			HashMap<String,String> accessTokens = (HashMap<String, String>) request.getSession().getAttribute("twitterAccessToken");
			
			BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(GlobalEntries.getGlobalEntries().getConfigManager().getHttpClientSocketRegistry());
			RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build();
			CloseableHttpClient http = HttpClients.custom().setConnectionManager(bhcm).setDefaultRequestConfig(rc).build();
			
			HttpUriRequest post = new HttpPost();
			
			try {
				post = RequestBuilder.post()
				        .setUri(new java.net.URI("https://api.twitter.com/oauth/access_token"))
				        .addParameter("oauth_verifier", oauthVerifier)
				        .build();
			} catch (URISyntaxException e) {
				throw new ServletException("Could not create post request");
			}
			
			
			
			this.signRequest(post, "oauth_verifier=" + oauthVerifier, accessTokens.get("oauth_token"), accessTokens.get("oauth_token_secret"), consumerKey, consumerSecret);
			
			CloseableHttpResponse httpResp = http.execute(post);
			
			BufferedReader in = new BufferedReader(new InputStreamReader(httpResp.getEntity().getContent()));
			
			StringBuffer token = new StringBuffer();
			
			
			String line = null;
			while ((line = in.readLine()) != null) {
				token.append(line);
			}
			
			
			EntityUtils.consumeQuietly(httpResp.getEntity());
			httpResp.close();
			
			
			System.err.println(token);
			
			List<NameValuePair> parsed = URLEncodedUtils.parse(token.toString(), Charsets.UTF_8);
			HashMap<String,String> userTokens = new HashMap<String,String>();
			
			for (NameValuePair nvp : parsed) {
				userTokens.put(nvp.getName(), nvp.getValue());
			}
			
			request.getSession().setAttribute("twitterUserToken", accessTokens);
			
			HttpGet get = new HttpGet("https://api.twitter.com/1.1/account/verify_credentials.json?include_email=true");
			this.signRequest(get, "", userTokens.get("oauth_token"), userTokens.get("oauth_token_secret"), consumerKey, consumerSecret);
			
			httpResp = http.execute(get);
			
			in = new BufferedReader(new InputStreamReader(httpResp.getEntity().getContent()));
			token.setLength(0);
			
			 line = null;
			while ((line = in.readLine()) != null) {
				token.append(line);
			}
			
			
			EntityUtils.consumeQuietly(httpResp.getEntity());
			httpResp.close();
			
			
			System.err.println(token);
			
			httpResp.close();
			bhcm.close();
			
			Map attrs = com.cedarsoftware.util.io.JsonReader.jsonToMaps(token.toString());
			
			if (! linkToDirectory) {
				loadUnlinkedUser(session, noMatchOU, uidAttr, act, attrs);
				
				as.setSuccess(true);

				
			} else {
				lookupUser(as, session, myvd, noMatchOU, uidAttr, lookupFilter, act, attrs);
			}
			
			
			String redirectToURL = request.getParameter("target");
			if (redirectToURL != null && ! redirectToURL.isEmpty()) {
				reqHolder.setURL(redirectToURL);
			}
			
			
			
			holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
			
		}
		
	}

	public void doPost(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	public void doPut(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	public void doHead(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	public void doOptions(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	public void doDelete(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}
	
	private void signRequest(HttpUriRequest request, String postParams,String token,String tokenSecret, String consumerKey,String consumerSecret) {
	    // TODO: this is a little odd: we already encoded the values earlier, but using URLEncodedUtils.parse will decode the values,
	    // which we will encode again.
	    List<NameValuePair> httpGetParams = null;
	    
	    if (request.getURI().getRawQuery() == null) {
	    	httpGetParams = new ArrayList<NameValuePair>();
	    } else {
	    	httpGetParams = URLEncodedUtils.parse(request.getURI().getRawQuery(), Charsets.UTF_8);
	    }
	    
	    
	    List<Pair> javaParams = new ArrayList<Pair>(httpGetParams.size());
	    for (NameValuePair params : httpGetParams) {
	      Pair tuple = new Pair(UrlCodec.encode(params.getName()), UrlCodec.encode(params.getValue()));
	      javaParams.add(tuple);
	    }

	    if (postParams != null) {
	      List<NameValuePair> httpPostParams = URLEncodedUtils.parse(postParams, Charsets.UTF_8);

	      for (NameValuePair params : httpPostParams) {
	        Pair tuple = new Pair(UrlCodec.encode(params.getName()), UrlCodec.encode(params.getValue()));
	        javaParams.add(tuple);
	      }
	    }

	    long timestampSecs = generateTimestamp();
	    String nonce = generateNonce();

	    OAuthParams.OAuth1Params oAuth1Params = new OAuthParams.OAuth1Params(
	      token, consumerKey, nonce, timestampSecs, Long.toString(timestampSecs), "",
	      OAuthParams.HMAC_SHA1, OAuthParams.ONE_DOT_OH
	    );

	    int port = request.getURI().getPort();
	    if (port <= 0) {
	      // getURI can return a -1 for a port
	      if (request.getURI().getScheme().equalsIgnoreCase(HttpConstants.HTTP_SCHEME)) {
	        port = HttpConstants.DEFAULT_HTTP_PORT;
	      } else if (request.getURI().getScheme().equalsIgnoreCase(HttpConstants.HTTPS_SCHEME)) {
	        port = HttpConstants.DEFAULT_HTTPS_PORT;
	      } else {
	        throw new IllegalStateException("Bad URI scheme: " + request.getURI().getScheme());
	      }
	    }

	    String normalized = Normalizer.getStandardNormalizer().normalize(
	        request.getURI().getScheme(), request.getURI().getHost(), port, request.getMethod().toUpperCase(),
	        request.getURI().getPath(), javaParams, oAuth1Params
	    );

	    String signature;
	    try {
	      signature = Signer.getStandardSigner().getString(normalized, tokenSecret, consumerSecret);
	    } catch (InvalidKeyException e) {
	      throw new RuntimeException(e);
	    } catch (NoSuchAlgorithmException e) {
	      throw new RuntimeException(e);
	    }

	    Map<String, String> oauthHeaders = new HashMap<String, String>();
	    oauthHeaders.put(OAuthParams.OAUTH_CONSUMER_KEY, quoted(consumerKey));
	    oauthHeaders.put(OAuthParams.OAUTH_TOKEN, quoted(token));
	    oauthHeaders.put(OAuthParams.OAUTH_SIGNATURE, quoted(signature));
	    oauthHeaders.put(OAuthParams.OAUTH_SIGNATURE_METHOD, quoted(OAuthParams.HMAC_SHA1));
	    oauthHeaders.put(OAuthParams.OAUTH_TIMESTAMP, quoted(Long.toString(timestampSecs)));
	    oauthHeaders.put(OAuthParams.OAUTH_NONCE, quoted(nonce));
	    oauthHeaders.put(OAuthParams.OAUTH_VERSION, quoted(OAuthParams.ONE_DOT_OH));
	    String header = Joiner.on(", ").withKeyValueSeparator("=").join(oauthHeaders);

	    request.setHeader(HttpHeaders.AUTHORIZATION, "OAuth " + header);

	  }

	  private String quoted(String str) {
	    return "\"" + str + "\"";
	  }

	  private long generateTimestamp() {
	    long timestamp = System.currentTimeMillis();
	    return timestamp / 1000;
	  }

	  private String generateNonce() {
	    return Long.toString(Math.abs(secureRandom.nextLong())) + System.currentTimeMillis();
	  }
	  
	  public static void lookupUser(AuthStep as, HttpSession session, MyVDConnection myvd, String noMatchOU, String uidAttr,
				String lookupFilter, AuthChainType act, Map jwtNVP) {
			boolean uidIsFilter = ! lookupFilter.isEmpty();
			
			
			String filter = "";
			if (uidIsFilter) {
				StringBuffer b = new StringBuffer();
				int lastIndex = 0;
				int index = lookupFilter.indexOf('$');
				while (index >= 0) {
					b.append(lookupFilter.substring(lastIndex,index));
					lastIndex = lookupFilter.indexOf('}',index) + 1;
					String reqName = lookupFilter.substring(index + 2,lastIndex - 1);
					b.append(jwtNVP.get(reqName).toString());
					index = lookupFilter.indexOf('$',index+1);
				}
				b.append(lookupFilter.substring(lastIndex));
				filter = b.toString();
			
			} else {
				StringBuffer b = new StringBuffer();
				String userParam = (String) jwtNVP.get(uidAttr);
				b.append('(').append(uidAttr).append('=').append(userParam).append(')');
				if (userParam == null) {
					filter = "(!(objectClass=*))";
				} else {
					filter = equal(uidAttr,userParam).toString();
				}
			}
			
			try {
				
				String root = act.getRoot();
				if (root == null || root.trim().isEmpty()) {
					root = "o=Tremolo";
				}
				
				LDAPSearchResults res = myvd.search(root, 2, filter, new ArrayList<String>());
				
				if (res.hasMore()) {
					LDAPEntry entry = res.next();
					
					
					Iterator<LDAPAttribute> it = entry.getAttributeSet().iterator();
					AuthInfo authInfo = new AuthInfo(entry.getDN(),(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),act.getName(),act.getLevel());
					((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(authInfo);
					
					while (it.hasNext()) {
						LDAPAttribute attrib = it.next();
						Attribute attr = new Attribute(attrib.getName());
						String[] vals = attrib.getStringValueArray();
						for (int i=0;i<vals.length;i++) {
							attr.getValues().add(vals[i]);
						}
						authInfo.getAttribs().put(attr.getName(), attr);
					}
					
					for (Object o : jwtNVP.keySet()) {
						String s = (String) o;
						String val = jwtNVP.get(s).toString();
						Attribute attr = authInfo.getAttribs().get(s);
						if (attr == null) {
							attr = new Attribute(s,val);
							authInfo.getAttribs().put(attr.getName(), attr);
						}
						
						if (! attr.getValues().contains(val)) {
							attr.getValues().add(val);
						}
								
						
						
						
					}
					
					as.setSuccess(true);
					
					
					
				} else {
					
					loadUnlinkedUser(session, noMatchOU, uidAttr, act, jwtNVP);
					
					as.setSuccess(true);
				}
				
			} catch (LDAPException e) {
				if (e.getResultCode() != LDAPException.INVALID_CREDENTIALS) {
					logger.error("Could not authenticate user",e);
				} 
				
				
				as.setSuccess(false);
			}
		}

		public static void loadUnlinkedUser(HttpSession session, String noMatchOU, String uidAttr, AuthChainType act,
				Map jwtNVP) {
			String uid = (String) jwtNVP.get(uidAttr);
			StringBuffer dn = new StringBuffer();
			dn.append(uidAttr).append('=').append(uid).append(",ou=").append(noMatchOU).append(",o=Tremolo");
			
			AuthInfo authInfo = new AuthInfo(dn.toString(),(String) session.getAttribute(ProxyConstants.AUTH_MECH_NAME),act.getName(),act.getLevel());
			((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).setAuthInfo(authInfo);
			
			for (Object o : jwtNVP.keySet()) {
				String s = (String) o;
				if (jwtNVP.get(s) != null) {
					Attribute attr = new Attribute(s,jwtNVP.get(s).toString());
					authInfo.getAttribs().put(attr.getName(), attr);
				}
				
			}
		}

}
