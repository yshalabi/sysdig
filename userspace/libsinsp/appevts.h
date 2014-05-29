///////////////////////////////////////////////////////////////////////////////
// app event parser
///////////////////////////////////////////////////////////////////////////////
class sinsp_appevtparser
{
public:
	enum parse_result
	{
		RES_OK = 0,
		RES_COMMA = 1,
		RES_FAILED = 2,
		RES_TRUNCATED = 3,
	};

	sinsp_appevtparser()
	{
		m_storage_size = 0;
		m_storage = NULL;
		m_res = sinsp_appevtparser::RES_OK;
		m_fragment_size = 0;
	}

	~sinsp_appevtparser()
	{
		if(m_storage)
		{
			free(m_storage);
		}
	}

	inline sinsp_appevtparser::parse_result process_event_data(char *data, uint32_t datalen)
	{
		ASSERT(data != NULL);

		//
		// Make sure we have enough space in the buffer and copy the data into it
		//
		if(m_storage_size < m_fragment_size + datalen + 1)
		{
			m_storage = (char*)realloc(m_storage, m_fragment_size + datalen + 1);
			if(m_storage == NULL)
			{
				throw sinsp_exception("memory allocation error in sinsp_appevtparser::process_event_data.");
			}
			m_storage_size = m_fragment_size + datalen + 1;
		}

		memcpy(m_storage + m_fragment_size, data, datalen);
		m_storage[m_fragment_size + datalen] = 0;

		if(m_fragment_size != 0)
		{
			m_fullfragment_storage_str = m_storage;
		}

		//
		// Do the parsing
		//
		parse(m_storage, m_fragment_size + datalen);

		if(m_res == sinsp_appevtparser::RES_FAILED)
		{
			//
			// Invalid syntax
			//
			m_fragment_size = 0;
			m_fullfragment_storage_str.clear();
			return m_res;
		}
		else if(m_res == sinsp_appevtparser::RES_TRUNCATED)
		{
			//
			// Valid syntax, but the message is incomplete. Buffer it and wait for
			// more fragments.
			//

			if(m_fragment_size > MAX_USER_EVT_BUFFER)
			{
				//
				// Maximum buffering size reached, drop the event
				//
				m_fragment_size = 0;
				return m_res;
			}

			if(m_fullfragment_storage_str.length() == 0)
			{
				memcpy(m_storage, 
					data, 
					datalen);

				m_storage[datalen] = 0;
				m_fragment_size += datalen;
			}
			else
			{
				uint32_t tlen = m_fullfragment_storage_str.length();

				memcpy(m_storage, 
					m_fullfragment_storage_str.c_str(), 
					tlen);

				m_fragment_size = tlen;
			}
		
			return m_res;
		}

		m_fragment_size = 0;
		m_fullfragment_storage_str.clear();

		return sinsp_appevtparser::RES_OK;
	}

	inline void parse(char* evtstr, uint32_t evtstrlen)
	{
		char* p;
		uint32_t delta;
		char* tstr;

		//
		// Reset the content
		//
		p = m_storage;
		m_tags.clear();
		m_argnames.clear();
		m_argvals.clear();
		m_taglens.clear();
		m_argnamelens.clear();
		m_argvallens.clear();
		m_tot_taglens = 0;
		m_tot_argnamelens = 0;
		m_tot_argvallens = 0;

		//
		// Skip the initial braket
		//
		m_res = skip_spaces(p, &delta);
		if(m_res != sinsp_appevtparser::RES_OK)
		{
			return;
		}
		p += delta;

		if(*(p++) != '[')
		{
			m_res = sinsp_appevtparser::RES_FAILED;
			return;
		}

		//
		// ID
		//
		m_res = skip_spaces(p, &delta);
		if(m_res != sinsp_appevtparser::RES_OK)
		{
			return;
		}
		p += delta;

		m_res = parsenumber(p, &m_id, &delta);
		if(m_res > sinsp_appevtparser::RES_COMMA)
		{
			return;
		}
		p += delta;

		if(m_res == sinsp_appevtparser::RES_COMMA)
		{
			m_res = skip_spaces(p, &delta);
		}
		else
		{
			m_res = skip_spaces_and_commas(p, &delta, 1);
		}

		if(m_res != sinsp_appevtparser::RES_OK)
		{
			return;
		}
		p += delta;

		//
		// Direction
		//
		if(*p == '>')
		{
			m_is_enter = true;
		}
		else if(*p == '<')
		{
			m_is_enter = false;
		}
		else
		{
			if(*p == 0)
			{
				m_res = sinsp_appevtparser::RES_TRUNCATED;
				return;
			}
			else
			{
				m_res = sinsp_appevtparser::RES_FAILED;
				return;
			}
		}
		p++;

		//
		// First tag
		//
		m_res = skip_spaces_and_commas_and_sq_brakets(p, &delta);
		if(m_res != sinsp_appevtparser::RES_OK)
		{
			return;
		}
		p += delta;

		m_res = parsestr_not_enforce(p, &tstr, &delta);
		if(m_res != sinsp_appevtparser::RES_OK)
		{
			return;
		}
		p += delta;

		if(tstr != NULL)
		{
			m_tags.push_back(tstr);
			m_taglens.push_back(delta - 2);
			m_tot_taglens += delta - 2;

			//
			// Remaining tags
			//
			while(true)
			{
				m_res = skip_spaces_and_commas(p, &delta, 0);
				if(m_res != sinsp_appevtparser::RES_OK)
				{
					return;
				}
				p += delta;

				if(*p == ']')
				{
					break;
				}

				m_res = parsestr(p, &tstr, &delta);
				if(m_res != sinsp_appevtparser::RES_OK)
				{
					return;
				}
				p += delta;
				m_tags.push_back(tstr);
				m_taglens.push_back(delta - 2);
				m_tot_taglens += delta - 2;
			}
		}

		//
		// First argument
		//
		m_res = skip_spaces_and_commas_and_all_brakets(p, &delta);
		if(m_res != sinsp_appevtparser::RES_OK)
		{
			return;
		}
		p += delta;

		m_res = parsestr_not_enforce(p, &tstr, &delta);
		if(m_res != sinsp_appevtparser::RES_OK)
		{
			return;
		}
		p += delta;
	
		if(tstr != NULL)
		{
			m_argnames.push_back(tstr);
			m_argnamelens.push_back(delta - 2);
			m_tot_argnamelens += delta - 2;

			m_res = skip_spaces_and_columns(p, &delta);
			if(m_res != sinsp_appevtparser::RES_OK)
			{
				return;
			}
			p += delta;

			m_res = parsestr(p, &tstr, &delta);
			if(m_res != sinsp_appevtparser::RES_OK)
			{
				return;
			}
			p += delta;
			m_argvals.push_back(tstr);
			m_argvallens.push_back(delta - 2);
			m_tot_argvallens += delta - 2;

			//
			// Remaining arguments
			//
			while(true)
			{
				m_res = skip_spaces_and_commas_and_cr_brakets(p, &delta);
				if(m_res != sinsp_appevtparser::RES_OK)
				{
					return;
				}
				p += delta;

				if(*p == ']')
				{
					p++;
					break;
				}

				m_res = parsestr(p, &tstr, &delta);
				if(m_res != sinsp_appevtparser::RES_OK)
				{
					return;
				}
				p += delta;
				m_argnames.push_back(tstr);
				m_argnamelens.push_back(delta - 2);
				m_tot_argnamelens += delta - 2;

				m_res = skip_spaces_and_columns(p, &delta);
				if(m_res != sinsp_appevtparser::RES_OK)
				{
					return;
				}
				p += delta;

				m_res = parsestr(p, &tstr, &delta);
				if(m_res != sinsp_appevtparser::RES_OK)
				{
					return;
				}
				p += delta;
				m_argvals.push_back(tstr);
				m_argvallens.push_back(delta - 2);
				m_tot_argvallens += delta - 2;
			}
		}

		//
		// Terminating ]
		//
		m_res = skip_spaces(p, &delta);
		if(m_res != sinsp_appevtparser::RES_OK)
		{
			return;
		}
		p += delta;

		if(*p != ']')
		{
			if(*p == 0)
			{
				m_res = sinsp_appevtparser::RES_TRUNCATED;
			}
			else
			{
				m_res = sinsp_appevtparser::RES_FAILED;
			}
			return;
		}

		m_res = sinsp_appevtparser::RES_OK;
		return;
	}

	bool m_is_enter;
	char* m_id;
	vector<char*> m_tags;
	vector<char*> m_argnames;
	vector<char*> m_argvals;
	vector<uint32_t> m_taglens;
	vector<uint32_t> m_argnamelens;
	vector<uint32_t> m_argvallens;
	pair<vector<char*>*, vector<char*>*> m_args;
	uint32_t m_tot_taglens;
	uint32_t m_tot_argnamelens;
	uint32_t m_tot_argvallens;

VISIBILITY_PRIVATE
	inline parse_result skip_spaces(char* p, uint32_t* delta)
	{
		char* start = p;

		while(*p == ' ')
		{
			if(*p == 0)
			{
				return sinsp_appevtparser::RES_TRUNCATED;
			}

			p++;
		}

		*delta = p - start;
		return sinsp_appevtparser::RES_OK;
	}

	inline parse_result skip_spaces_and_commas(char* p, uint32_t* delta, uint32_t n_expected_commas)
	{
		char* start = p;
		uint32_t nc = 0;

		while(true)
		{
			if(*p == ' ')
			{
				p++;
				continue;
			}
			else if(*p == ',')
			{
				nc++;
			}
			else if(*p == 0)
			{
				return sinsp_appevtparser::RES_TRUNCATED;
			}
			else
			{
				break;
			}

			p++;
		}

		if(nc < n_expected_commas)
		{
			return sinsp_appevtparser::RES_FAILED;
		}

		*delta = p - start;
		return sinsp_appevtparser::RES_OK;
	}

	inline parse_result skip_spaces_and_columns(char* p, uint32_t* delta)
	{
		char* start = p;
		uint32_t nc = 0;

		while(*p == ' ' || *p == ':' || *p == 0)
		{
			if(*p == 0)
			{
				return sinsp_appevtparser::RES_TRUNCATED;
			}
			else if(*p == ':')
			{
				nc++;
			}

			p++;
		}

		if(nc != 1)
		{
			return sinsp_appevtparser::RES_FAILED;
		}

		*delta = p - start;
		return sinsp_appevtparser::RES_OK;
	}

	inline parse_result skip_spaces_and_commas_and_sq_brakets(char* p, uint32_t* delta)
	{
		char* start = p;
		uint32_t nc = 0;
		uint32_t nosb = 0;

		while(*p == ' ' || *p == ',' || *p == '[' || *p == ']' || *p == 0)
		{
			if(*p == 0)
			{
				return sinsp_appevtparser::RES_TRUNCATED;
			}
			else if(*p == ',')
			{
				nc++;
			}
			else if(*p == '[')
			{
				nosb++;
			}
			else if(*p == ']')
			{
				if(nosb != 0)
				{
					break;
				}
			}

			p++;
		}

		if(nc != 1 || nosb != 1)
		{
			return sinsp_appevtparser::RES_FAILED;
		}

		*delta = p - start;
		return sinsp_appevtparser::RES_OK;
	}

	inline parse_result skip_spaces_and_commas_and_cr_brakets(char* p, uint32_t* delta)
	{
		char* start = p;
		uint32_t nc = 0;
		uint32_t nocb = 0;
		uint32_t nccb = 0;

		while(*p == ' ' || *p == ',' || *p == '{' || *p == '}' || *p == 0)
		{
			if(*p == 0)
			{
				return sinsp_appevtparser::RES_TRUNCATED;
			}
			else if(*p == ',')
			{
				nc++;
			}
			else if(*p == '{')
			{
				nocb++;
			}
			else if(*p == '}')
			{
				nccb++;
			}

			p++;
		}

		if(!((nc == 1 && nocb == 1) || (nc == 1 && nccb == 1) || (nccb == 1 && *p == ']')))
		{
			return sinsp_appevtparser::RES_FAILED;
		}

		*delta = p - start;
		return sinsp_appevtparser::RES_OK;
	}

	inline parse_result skip_spaces_and_commas_and_all_brakets(char* p, uint32_t* delta)
	{
		char* start = p;
		uint32_t nc = 0;
		uint32_t nosb = 0;
		uint32_t nocb = 0;

		while(*p == ' ' || *p == ',' || *p == '[' || *p == ']' || *p == '{' || *p == '}' || (*p == 0))
		{
			if(*p == 0)
			{
				return sinsp_appevtparser::RES_TRUNCATED;
			}
			else if(*p == ',')
			{
				nc++;
			}
			else if(*p == '[')
			{
				nosb++;
			}
			else if(*p == ']')
			{
				if(nosb != 0)
				{
					break;
				}
			}
			else if(*p == '{')
			{
				nocb++;
			}

			p++;
		}

		if(nc != 1 || nosb != 1)
		{
			return sinsp_appevtparser::RES_FAILED;
		}
		else if(nocb != 1)
		{
			if(*p != ']')
			{
				return sinsp_appevtparser::RES_FAILED;
			}
		}

		*delta = p - start;
		return sinsp_appevtparser::RES_OK;
	}

	inline parse_result parsestr(char* p, char** res, uint32_t* delta)
	{
		char* initial = p;
		*res = NULL;

		if(*p != '"')
		{
			*delta = (p - initial + 1);
			if(*p == 0)
			{
				return sinsp_appevtparser::RES_TRUNCATED;
			}
			else
			{
				return sinsp_appevtparser::RES_FAILED;
			}
		}

		*res = p + 1;
		p++;

		while(*p != '\"')
		{
			if(*p == 0)
			{
				*delta = (p - initial + 1);
				return sinsp_appevtparser::RES_TRUNCATED;
			}

			p++;
		}

		*p = 0;

		*delta = (p - initial + 1);
		return sinsp_appevtparser::RES_OK;
	}

	inline parse_result parsestr_not_enforce(char* p, char** res, uint32_t* delta)
	{
		sinsp_appevtparser::parse_result psres = parsestr(p, res, delta);

		if(psres == sinsp_appevtparser::RES_FAILED)
		{
			if(*(p + *delta) == ']')
			{
				*res = NULL;
				return sinsp_appevtparser::RES_OK;
			}
		}
		else if(psres == sinsp_appevtparser::RES_TRUNCATED)
		{
			return psres;
		}

		return sinsp_appevtparser::RES_OK;
	}

	inline parse_result parsenumber(char* p, char** res, uint32_t* delta)
	{
/*
		char* start = p;
		sinsp_appevtparser::parse_result retval = sinsp_appevtparser::RES_OK;
		uint64_t val = 0;

		while(*p >= '0' && *p <= '9')
		{
			val = val * 10 + (*p - '0');
			p++;
		}

		if(*p == ',')
		{
			retval = sinsp_appevtparser::RES_COMMA;
		}
		else if(*p != 0 && *p != ' ')
		{
			return sinsp_appevtparser::RES_FAILED;
		}
		else if(*p == 0)
		{
			return sinsp_appevtparser::RES_TRUNCATED;
		}


		*p = 0;

		*res = val;
		*delta = (p - start + 1);
		return retval;
*/
		char* start = p;
		sinsp_appevtparser::parse_result retval = sinsp_appevtparser::RES_OK;

		*res = p;

		while(*p >= '0' && *p <= '9')
		{
			p++;
		}

		if(*p == ',')
		{
			retval = sinsp_appevtparser::RES_COMMA;
		}
		else if(*p != 0 && *p != ' ')
		{
			return sinsp_appevtparser::RES_FAILED;
		}
		else if(*p == 0)
		{
			return sinsp_appevtparser::RES_TRUNCATED;
		}


		*p = 0;

		*delta = (p - start + 1);
		return retval;
	}

	char* m_storage;
	uint32_t m_storage_size;
	uint32_t m_fragment_size;
	sinsp_appevtparser::parse_result m_res;
	string m_fullfragment_storage_str;

	friend class sinsp_parser;
};

///////////////////////////////////////////////////////////////////////////////
// app table entry
///////////////////////////////////////////////////////////////////////////////
class sinsp_partial_appevt
{
public:
	sinsp_partial_appevt()
	{
		m_tags = (char*)malloc(UESTORAGE_INITIAL_BUFSIZE);
		m_args = (char*)malloc(UESTORAGE_INITIAL_BUFSIZE);
		m_tags_size = UESTORAGE_INITIAL_BUFSIZE;
		m_args_size = UESTORAGE_INITIAL_BUFSIZE;
	}

	~sinsp_partial_appevt()
	{
		if(m_tags)
		{
			free(m_tags);
		}

		if(m_args)
		{
			free(m_args); 
		}
	}

	void init(sinsp_appevtparser* details)
	{
		vector<char*>::iterator it;
		vector<uint32_t>::iterator sit;

		if(m_tags_size < details->m_tot_argvallens)
		{
			m_tags = (char*)realloc(m_tags, details->m_tot_argvallens);
			m_tags_size = details->m_tot_argvallens;
		}

		ASSERT(details->m_tags.size() == details->m_taglens.size());
		ASSERT(details->m_argnames.size() == details->m_argnamelens.size());
		ASSERT(details->m_argvals.size() == details->m_argvallens.size());
		
		char* p = m_tags;
		for(it = details->m_tags.begin(), sit = details->m_taglens.begin(); 
			it != details->m_tags.end(); ++it, ++sit)
		{
			memcpy(p, *it, *sit);
			p += *sit;
		}
	}

	char* m_tags;
	char* m_args;
	uint32_t m_tags_size;
	uint32_t m_args_size;
};
