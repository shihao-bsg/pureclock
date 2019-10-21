from oauth2client.service_account import ServiceAccountCredentials
import gspread

scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']

credentials = ServiceAccountCredentials.from_json_keyfile_name('sheet-01dbb67d486d.json', scope)

gc = gspread.authorize(credentials)

wks = gc.open('Test').sheet1


# print(wks.get_all_records())
# wks.append_row(['this goes into first column', 'this goes into second column'])
# wks.delete_row(2)
def import_data(user):
    if user.bookmarks.count() > 0:
        for bookmark in user.bookmarks:
            wks.clear()
            wks.append_row([bookmark.company, bookmark.time])
