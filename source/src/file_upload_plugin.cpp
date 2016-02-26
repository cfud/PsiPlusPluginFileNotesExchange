/*
* file_upload_plugin.cpp - plugin
* Copyright (C) 2016 cfud.biz
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this library; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*
*/

#include <QObject>
#include <QFileDialog>
#include <QByteArray>
#include <QFile>
#include <QMessageBox>
#include <QInputDialog>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrl>
#include <QProgressDialog>
#include <QSslError>
#include <QFileInfo>
#include <QVBoxLayout>
#include <QLabel>
#include <QTextEdit>
#include <QClipboard>
#include <QApplication>

#include <openssl/evp.h>
#include <openssl/aes.h>

#include "psiplugin.h"
#include "iconfactoryaccessinghost.h"
#include "iconfactoryaccessor.h"
#include "plugininfoprovider.h"
#include "toolbariconaccessor.h"
#include "gctoolbariconaccessor.h"
#include "activetabaccessinghost.h"
#include "activetabaccessor.h"
#include "contactinfoaccessor.h"
#include "contactinfoaccessinghost.h"
#include "optionaccessor.h"
#include "optionaccessinghost.h"
#include "shortcutaccessor.h"
#include "shortcutaccessinghost.h"

#include "screenshot.h"

const char *cfudUrl = "https://cfud.biz/cryptosharing/sendFile/";
const int maxFileSize = 10485760;


//----------------------------------------------------------------
// A E S E n c r y p t
//----------------------------------------------------------------

class AESEncrypt {
	unsigned char mKey[EVP_MAX_KEY_LENGTH];
	unsigned char mIV[EVP_MAX_IV_LENGTH];
	EVP_CIPHER_CTX *mCtx;
	unsigned char *mCipherText;
	int mCipherTextLen;
	unsigned char mSalt[8];

public:
	AESEncrypt() : mCipherText(0), mCipherTextLen(0) {
		memset(mKey, 0, EVP_MAX_KEY_LENGTH);
		memset(mIV, 0, EVP_MAX_IV_LENGTH);
		memset(mSalt, 0, 8);
		mCtx = 0;
	}

	~AESEncrypt() {
		if (mCtx) {
			EVP_CIPHER_CTX_free(mCtx);
		}
		if (mCipherText) {
			free(mCipherText);
		}
	}

	bool Run(QByteArray &plain, QString &password) {
		InitSSL();
		if (!SetPassword(password)) {
			return false;
		}

		return Encrypt(plain);
	}

	const char *data() const {
		return (char*)mCipherText;
	}

	int size() const {
		return mCipherTextLen;
	}

	QByteArray format() {
		QByteArray res;
		res.append("Salted__");
		res.append((char*)mSalt, 8);
		res.append((char*)mCipherText, mCipherTextLen);
		return res.toBase64();
	}

private:
	bool SetPassword(QString &password) {
		const EVP_CIPHER *cipher = EVP_aes_256_cbc();
		const EVP_MD *md = EVP_md5();
		if (!md || !cipher) {
			return false;
		}

		QByteArray data = password.toUtf8();
		for (int i = 0; i < 8; i++) {
			mSalt[i] = qrand() % 255;
		}
		if (!EVP_BytesToKey(cipher, md, mSalt,
			(unsigned char*)data.data(), data.size(), 1, mKey, mIV)) {
			return false;
		}
		
		return true;
	}

	bool Encrypt(QByteArray &plain) {
		mCtx = EVP_CIPHER_CTX_new();
		if (!mCtx) {
			return false;
		}
		if (EVP_EncryptInit_ex(mCtx, EVP_aes_256_cbc(), 0, mKey, mIV) != 1) {
			return false;
		}
		int n = plain.size() + 1 + AES_BLOCK_SIZE;
		unsigned char *ciphertext = (unsigned char*)malloc(n + 1);
		memset(ciphertext, 0, n + 1);
		
		if (EVP_EncryptUpdate(mCtx, ciphertext, &n, 
			(unsigned char*)plain.data(), plain.size()) != 1) {
			free(ciphertext);
			return false;
		}

		int finalBytes = 0;
		if (EVP_EncryptFinal_ex(mCtx, ciphertext + n, &finalBytes) != 1) {
			free(ciphertext);
			return false;
		}

		n += finalBytes;
		mCipherText = ciphertext;
		mCipherTextLen = n;
		return true;
	}

	void InitSSL() {
		static bool done = false;
		if (done) {
			return;
		}
		done = true;
		OpenSSL_add_all_algorithms();
	}

};


//----------------------------------------------------------------
// U p l o a d e r
//----------------------------------------------------------------

class Uploader : public QObject {
	Q_OBJECT
public:
	QString mFileName;
	QString mBaseName;
	QString mPassword;
	QNetworkAccessManager *mManager;
	QProgressDialog *mProgress;
	QNetworkReply *mReply;
	QByteArray mReplyData;

	Uploader() : mManager(0), mProgress(0), mReply(0) {}

	~Uploader() {
	}

	void InitPassword() {
		char charset[1024] = { 0 };
		int charsetIdx = 0;
		for (int i = 'a'; i < 'z'; i++) {
			charset[charsetIdx++] = i;
		}
		
		for (int i = 'A'; i < 'Z'; i++) {
			charset[charsetIdx++] = i;
		}

		for (int i = '0'; i < '9'; i++) {
			charset[charsetIdx++] = i;
		}

		for (int i = 0; i < 20; i++) {
			int idx = qrand() % charsetIdx;
			mPassword.append(charset[idx]);
		}
	}

	bool Run(QString &fileName) {
		QFile file(fileName);
		if (!file.open(QIODevice::ReadOnly)) {
			QMessageBox::warning(0, "CFUD File Upload",
				QString("Open file failed: %1").arg(fileName));
			return false;
		}

		QFileInfo fileInfo(file);
		mBaseName = fileInfo.fileName();

		if (file.size() > maxFileSize) {
			QMessageBox::warning(0, "CFUD File Upload",
				QString("maximum file size: 10 mb"));
			return false;
		}

		QByteArray fileData = file.readAll();
		if (fileData.isEmpty()) {
			QMessageBox::warning(0, "CFUD File Upload",
				QString("0 bytes read: %1").arg(fileName));
			return false;
		}

		mFileName = fileName;
		return Run(fileData, mBaseName);
	}

	bool Run(QByteArray &fileData, QString fileName, bool isImage=false) {
		InitPassword();
		bool ok;

		mPassword = QInputDialog::getText(0, "CFUD", 
			"Password:", QLineEdit::Normal, mPassword, &ok);
		if (!ok) {
			return false;
		}

		QByteArray tmp;
		if (isImage)
			tmp.append("data:image/png;base64,");
		else
			tmp.append("data:application/x-msdownload;base64,");
		
		tmp.append(fileData.toBase64());

		AESEncrypt aes;
		if (!aes.Run(tmp, mPassword)) {
			QMessageBox::warning(0, "CFUD File Upload",
				QString("file encryption failed: %1").arg(fileName));
			return false;
		}

		mManager = new QNetworkAccessManager(this);
		connect(mManager, SIGNAL(finished(QNetworkReply*)),
			this, SLOT(replyFinished(QNetworkReply*)));
		connect(mManager, SIGNAL(sslErrors(QNetworkReply*, QList<QSslError>)), 
			this, SLOT(onSslError(QNetworkReply*, QList<QSslError>)));

		QNetworkRequest request;
		request.setUrl(QUrl(cfudUrl));
	
		request.setHeader(
			QNetworkRequest::ContentTypeHeader,
			QString("application/x-www-form-urlencoded; charset=utf-8"));
		
		QByteArray encFile = aes.format();
		QByteArray postData;
		postData.append("data=");
		postData.append(encFile.toPercentEncoding(QByteArray(), QByteArray("+")));
		postData.append("&name=");
		postData.append(fileName.toUtf8().toPercentEncoding());

		mReply = mManager->post(request, postData);

		connect(mReply, SIGNAL(uploadProgress(qint64, qint64)),
			this, SLOT(uploadProgress(qint64, qint64)));

		mProgress = new QProgressDialog("uploading", "cancel", 0, postData.size());
		mProgress->setWindowModality(Qt::ApplicationModal);
		//mProgress->setMinimumDuration(0);
		mProgress->show();
		connect(mProgress, SIGNAL(canceled()), this, SLOT(uploadCancel()));
		
		return true;
	}

public slots:
	void replyFinished(QNetworkReply *reply) {
		mProgress->hide();

		if (reply->error() != QNetworkReply::NoError) {
			QMessageBox::warning(0, "CFUD File Upload", reply->errorString());
			reply->deleteLater();
			deleteLater();
			return;
		}

		mReplyData = reply->readAll();

		emit completed(this);
		reply->deleteLater();
	}

	void onSslError(QNetworkReply *reply, QList<QSslError> errorList) {
		Q_UNUSED(errorList);
		reply->ignoreSslErrors();
	}

	void uploadProgress(qint64 sent, qint64 total) {
		if (total <= 0) {
			return;
		}
		mProgress->setMaximum(total);
		mProgress->setValue(sent);
	}

	void uploadCancel() {
		mProgress->hide();
		mReply->abort();
	}

signals:
	void completed(Uploader *self);
};




//----------------------------------------------------------------
// F i l e U p l o a d P l u g i n
//----------------------------------------------------------------

class FileUploadPlugin :
	public QObject,
	public PsiPlugin,
	//public PluginInfoProvider,
	public IconFactoryAccessor,
	public ActiveTabAccessor,
	public ToolbarIconAccessor,
	public GCToolbarIconAccessor,
	public ContactInfoAccessor,
	public OptionAccessor,
	public ShortcutAccessor
{
	Q_OBJECT
	Q_INTERFACES(
		PsiPlugin
		//PluginInfoProvider
		IconFactoryAccessor
		ActiveTabAccessor
		ToolbarIconAccessor
		GCToolbarIconAccessor
		ContactInfoAccessor
		OptionAccessor
		ShortcutAccessor
		)

public:
	bool mEnabled;
	IconFactoryAccessingHost *mIconFactoryHost;
	ActiveTabAccessingHost *mActiveTab;
	OptionAccessingHost *mOptions;
	ShortcutAccessingHost *mShortcutHost;

	FileUploadPlugin() :
		mEnabled(false),
		mIconFactoryHost(0),
		mActiveTab(0),
		mOptions(0),
		mShortcutHost(0) {}

	~FileUploadPlugin() {}

	// PsiPlugin

	virtual QString name() const {
		return "CFUD File Upload Plugin";
	}
	virtual QString shortName() const {
		return "cfud";
	}

	virtual QString version() const {
		return "0.0.2";
	}

	virtual QWidget* options() {
		if (!mEnabled) {
			return 0;
		}
		QWidget *optionsWid = new QWidget();
		QVBoxLayout *vbox = new QVBoxLayout(optionsWid);
		QLabel *url = new QLabel("<a href=\"http://cfud.biz\">CFUD</a>", optionsWid);
		url->setOpenExternalLinks(true);
		vbox->addWidget(url);

		QLabel *text = new QLabel("screenshot shortcut: Alt+Shift+P", optionsWid);
		vbox->addWidget(text);

		vbox->addStretch();
		return optionsWid;
	}

	virtual bool enable();

	virtual bool disable() {
		mShortcutHost->disconnectShortcut(QKeySequence("alt+shift+p"),
			this, SLOT(makeScreen()));

		mEnabled = false;
		return true;
	}

	virtual void applyOptions() {}
	virtual void restoreOptions() {}

	virtual QPixmap icon() const {
		return QPixmap(":/cfud_file_upload/upload.png");
	}

	// PluginInfoProvider
	virtual QString pluginInfo() {
		return "";
	}

	// ToolbarIconAccessor
	virtual QList<QVariantHash> getButtonParam();

	virtual QAction* getAction(QObject* parent, int accountIndex,
		const QString& contact) {
		Q_UNUSED(parent);
		Q_UNUSED(accountIndex);
		Q_UNUSED(contact);
		return 0;
	}
	
	// GCToolbarIconAccessor

	virtual QList<QVariantHash> getGCButtonParam() {
		return getButtonParam();

	}
	virtual QAction* getGCAction(QObject*, int, const QString&) { 
		return 0; 
	}

	// IconFactoryAccessor
	virtual void setIconFactoryAccessingHost(IconFactoryAccessingHost* host) {
		mIconFactoryHost = host;
	}

	// ActiveTabAccessor
	virtual void setActiveTabAccessingHost(ActiveTabAccessingHost* host) {
		mActiveTab = host;
	}

	// ContactInfoAccessor
	virtual void setContactInfoAccessingHost(ContactInfoAccessingHost* host) {
		Q_UNUSED(host);
	}

	// OptionAccessor
	virtual void setOptionAccessingHost(OptionAccessingHost* host) {
		Q_UNUSED(host);
		mOptions = host;
	}

	virtual void optionChanged(const QString& option) {
		Q_UNUSED(option);
	}

	// ShortcutAccessor

	virtual void setShortcutAccessingHost(ShortcutAccessingHost* host) {
		mShortcutHost = host;
	}
	
	virtual void setShortcuts() {
		mShortcutHost->connectShortcut(QKeySequence("alt+shift+p"),
			this, SLOT(makeScreen()));
	}

public slots:
	void toolButtonPressed();
	void uploadCompleted(Uploader *uploader);
	void makeScreen();
};

Q_EXPORT_PLUGIN(FileUploadPlugin)


bool FileUploadPlugin::enable() {
	if (mEnabled) {
		return true;
	}
	QFile file(":/cfud_file_upload/upload.png");
	if (file.open(QIODevice::ReadOnly)) {
		mEnabled = true;
		QByteArray ico = file.readAll();
		mIconFactoryHost->addIcon("cfud_file_upload/upload", ico);
		file.close();
		return true;
	}
	mEnabled = false;
	return false;
}

QList<QVariantHash> FileUploadPlugin::getButtonParam() {
	QVariantHash hash;
	hash["tooltip"] = QVariant(tr("CFUD File Upload"));
	hash["icon"] = QVariant(QString("cfud_file_upload/upload"));
	hash["reciver"] = qVariantFromValue(qobject_cast<QObject *>(this));
	hash["slot"] = QVariant(SLOT(toolButtonPressed()));

	QList< QVariantHash > l;
	l.push_back(hash);
	return l;
}

void FileUploadPlugin::toolButtonPressed() {
	QString fileName = QFileDialog::getOpenFileName(0, tr("Open Image"));
	if (fileName.isEmpty()) {
		return;
	}

	Uploader *uploader = new Uploader();
	if (!uploader->Run(fileName)) {
		return;
	}
	connect(uploader, SIGNAL(completed(Uploader*)),
		this, SLOT(uploadCompleted(Uploader*)));
}

void FileUploadPlugin::uploadCompleted(Uploader *uploader) {
	uploader->deleteLater();

	QString text = uploader->mReplyData;
	text += "\npassword: ";
	text += uploader->mPassword;
	
	QApplication::clipboard()->setText(text);

	QTextEdit *ed = mActiveTab->getEditBox();
	if (ed) {
		if (!ed->textCursor().atStart()) {
			ed->textCursor().insertText("\n");
		}
		ed->textCursor().insertText(text);
	}
	else {
		QMessageBox::information(0, "CFUD File Upload",
			QString("upload details saved to clipboard, use Ctrl+V to paste it somewhere"));
	}
}

void FileUploadPlugin::makeScreen() {
	Screenshot screenshot;
	if (!screenshot.captureArea()) {
		return;
	}
	
	QByteArray png;
	QBuffer buffer(&png);
	buffer.open(QIODevice::WriteOnly);
	screenshot.pixmap().save(&buffer, "PNG");

	Uploader *uploader = new Uploader();
	if (!uploader->Run(png, "screenshot.png", true)) {
		return;
	}
	connect(uploader, SIGNAL(completed(Uploader*)),
		this, SLOT(uploadCompleted(Uploader*)));
}

#include "file_upload_plugin.moc"