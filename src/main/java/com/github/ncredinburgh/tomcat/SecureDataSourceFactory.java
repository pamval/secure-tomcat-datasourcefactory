package com.github.ncredinburgh.tomcat;

import static com.github.ncredinburgh.tomcat.PropertyParser.parseProperties;
import static javax.xml.bind.DatatypeConverter.parseBase64Binary;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import javax.naming.Context;
import javax.sql.DataSource;

import org.apache.tomcat.jdbc.pool.DataSourceFactory;

/**
 * A {@link DataSourceFactory} that supports an encrypted password.
 * The datasource assumes that the <code>password</code> property contains an encrypted password and 
 * decrypts it using the configured {@link ConfigurableDecryptor}.
 */
public class SecureDataSourceFactory extends DataSourceFactory {
		
	private Decryptor decryptor = new ConfigurableDecryptor();
	private Map<String, String> passwordCache = new ConcurrentHashMap<String, String>( );
			
	@Override
	public DataSource createDataSource(Properties properties, Context context, boolean XA) throws Exception {
		validate(properties);
		replacePassword(properties);
		
		return super.createDataSource(properties, context, XA);
	}

	private String getPassword ( String key ) {
		return passwordCache.getOrDefault( key, null );
	}

	private void setPassword (String key, String password) {
		passwordCache.put( key, password );

	}

	private void replacePassword(Properties properties) throws DecryptionException {
		String dataSourceKey = properties.getProperty(PROP_URL) + ";" + properties.getProperty(PROP_PASSWORD) + ";" + properties.getProperty(PROP_CONNECTIONPROPERTIES);
		if (getPassword( dataSourceKey ) == null) {
			setPassword( dataSourceKey, decryptPassword( properties ) );
		}
		properties.setProperty(PROP_PASSWORD, getPassword( dataSourceKey ));
	}
	
	private String decryptPassword(Properties properties) throws DecryptionException {
		byte[] cipherBytes = parseBase64Binary(properties.getProperty(PROP_PASSWORD));
		decryptor.configure(parseProperties(properties.getProperty(PROP_CONNECTIONPROPERTIES)));
		return new String(decryptor.decrypt(cipherBytes));
	}
	
	private void validate(Properties properties) throws DecryptionException {
		if (!properties.containsKey(PROP_PASSWORD)) {
			throw new DecryptionException("Property '" + PROP_PASSWORD +"' not specified");
		}
		if (!properties.containsKey(PROP_CONNECTIONPROPERTIES)) {
			throw new DecryptionException("Property '" + PROP_CONNECTIONPROPERTIES +"' not specified");
		}
	}
	
}
