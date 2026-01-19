export async function initForward(c, params) {

	const { workerName, domainList, token } = params;

	let headers = {
		Authorization: `Bearer ${token}`
	};

	let mainList = [];
	const childList = [];

	//查询DOMAIN变量对应域名
	for (let domain of domainList) {

		// 提取一级域名(主域名 + 顶级域名)
		const parts = domain.split('.');

		let paramDomain = domain
		if (parts.length > 2) {
			paramDomain = parts.slice(-2).join('.');
		}

		//结尾匹配查询域名
		const res = await fetch(`https://api.cloudflare.com/client/v4/zones?name=ends_with:${paramDomain}`, {
			method: 'GET',
			headers
		});

		const body = await res.json();

		if(!res.ok) {
			return c.json(body);
		}

		const { result } = body;

		result.forEach(item => {

			if (domain === item.name) {
				mainList.push({ domain: item.name, domainId: item.id });
			} else if (domain.includes(item.name)) {
				mainList.push({ domain: item.name, domainId: item.id });
				childList.push({ domain, domainId: item.id });
			}

		})

	}

	mainList  = [...new Set(mainList)];

	if (mainList.length === 0) {
		return c.text('Domain does not exist.');
	}

	//开启主域名电子邮件路由
	for (const { domainId } of mainList) {

		const res = await fetch(`https://api.cloudflare.com/client/v4/zones/${domainId}/email/routing/enable`, {
			method: 'POST',
			headers
		});

		const body = await res.json();

		if(!res.ok) {
			return c.json(body);
		}

	}


	//开启catch_all转发到worker
	for (const { domainId } of mainList) {

		const res = await fetch(`https://api.cloudflare.com/client/v4/zones/${domainId}/email/routing/rules/catch_all`, {
			method: 'PUT',
			headers,
			body: JSON.stringify({
				actions: [
					{
						type: "worker",
						value: [workerName]
					}
				],
				matchers: [
					{
						type: "all"
					}
				],
				enabled: true
			})
		});

		const body = await res.json();

		if(!res.ok) {
			return c.json(body);
		}

	}

	//开启子域名电子邮件路由
	for (const { domain, domainId } of childList) {

		const res = await fetch(`https://api.cloudflare.com/client/v4/zones/${domainId}/email/routing/enable`, {
			method: 'POST',
			headers,
			body: JSON.stringify({
				name: domain
			})
		});

		const body = await res.json();

		if(!res.ok) {
			return c.json(body);
		}

	}

	return c.text('success');

}
