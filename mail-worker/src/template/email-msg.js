export default function emailMsgTemplate(email, tgMsgTo, tgMsgFrom) {

	let template = `<b>${email.subject}</b>`

		if (tgMsgFrom === 'only-name') {
			template += `

发件人：${email.name}`
		}

		if (tgMsgFrom === 'show') {
			template += `

发件人：${email.name}  &lt;${email.sendEmail}&gt;`
		}

		if(tgMsgTo === 'show' && tgMsgFrom === 'hide') {
			template += `

收件人：\u200B${email.toEmail}`
			return template
		}

	if(tgMsgTo === 'show') {
		template += `
收件人：\u200B${email.toEmail}`
	}

		return template;

}
