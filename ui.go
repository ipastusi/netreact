package main

import (
	"fmt"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"log"
	"os"
	"strconv"
	"time"
)

// columns

type Column struct {
	name  string
	width int
}

var columns = []Column{
	{"IP Address", 18},
	{"MAC Address", 20},
	{"MAC Vendor", 30},
	{"First seen", 22},
	{"Last seen", 22},
	{"Packet count", 14},
}

// ui data structure

type UIEntry struct {
	IP        string
	MAC       string
	MACVendor string
	FirstTs   string
	LastTs    string
	Count     int
}

// virtual table: https://github.com/rivo/tview/wiki/VirtualTable

type UIApp struct {
	tview.TableContentReadOnly
	app  *tview.Application
	data *[]UIEntry
}

func newUIApp() *UIApp {
	return &UIApp{
		TableContentReadOnly: tview.TableContentReadOnly{},
		app:                  tview.NewApplication(),
		data:                 &[]UIEntry{},
	}
}

func (uiApp *UIApp) upsertAndRefreshTable(extArpEvent ExtendedArpEvent) {
	defer uiApp.app.Draw()
	ip := extArpEvent.ip.String()
	mac := extArpEvent.mac.String()
	timeFormat := "2006-01-02 15:04:05"
	firstTs := time.UnixMilli(extArpEvent.firstTs).Format(timeFormat)
	lastTs := time.UnixMilli(extArpEvent.ts).Format(timeFormat)
	macVendor := extArpEvent.macVendor

	// update, if found
	hosts := uiApp.data
	for i := 0; i < len(*hosts); i++ {
		if (*hosts)[i].IP == ip && (*hosts)[i].MAC == mac {
			(*hosts)[i].LastTs = lastTs
			(*hosts)[i].Count = extArpEvent.count
			return
		}
	}

	// insert, if new
	*hosts = append(*hosts, UIEntry{
		IP:        ip,
		MAC:       mac,
		MACVendor: macVendor,
		FirstTs:   firstTs,
		LastTs:    lastTs,
		Count:     1,
	})
}

func (uiApp *UIApp) GetCell(row int, col int) *tview.TableCell {
	entry := (*uiApp.data)[row]
	if col == 0 {
		paddedHostIP := " " + entry.IP
		return tview.NewTableCell(alignLeft(paddedHostIP, columns[0].width-1))
	} else if col == 1 {
		return tview.NewTableCell(alignLeft(entry.MAC, columns[1].width-1))
	} else if col == 2 {
		macVendor := entry.MACVendor
		if len(entry.MACVendor) > columns[2].width {
			maxTruncatedLen := columns[2].width - 3
			truncatedLen := min(len(entry.MACVendor), maxTruncatedLen)
			truncatedMacVendor := entry.MACVendor[:truncatedLen]
			macVendor = fmt.Sprintf("%v...", truncatedMacVendor)
		}
		return tview.NewTableCell(alignLeft(macVendor, columns[2].width-1))
	} else if col == 3 {
		return tview.NewTableCell(alignLeft(entry.FirstTs, columns[3].width-1))
	} else if col == 4 {
		return tview.NewTableCell(alignLeft(entry.LastTs, columns[4].width-1))
	} else {
		return tview.NewTableCell(alignRight(strconv.Itoa(entry.Count), columns[5].width-2))
	}
}

func (uiApp *UIApp) GetRowCount() int {
	return len(*uiApp.data)
}

func (uiApp *UIApp) GetColumnCount() int {
	return len(columns)
}

// load the UI

func loadUI(uiApp *UIApp, ifaceName string) {
	headerRow := getHeaderRow()
	table := tview.NewTable().SetEvaluateAllRows(false)
	table.SetContent(uiApp)

	newTextView := func(text string, align int) tview.Primitive {
		return tview.NewTextView().
			SetTextAlign(align).
			SetText(text)
	}

	titleBar := fmt.Sprintf(" Netreact  |  Interface: %v ", ifaceName)
	menuBar := fmt.Sprintf(" ▲ - Scroll Up  |  ▼ - Scroll Down  |  Q / ESC - Quit")
	grid := tview.NewGrid().
		SetRows(1, 1, 0, 1).
		SetColumns(0, 0, 0, 0).
		SetBorders(true).
		AddItem(newTextView(titleBar, tview.AlignLeft), 0, 0, 1, 4, 0, 0, false).
		AddItem(newTextView(headerRow, tview.AlignLeft), 1, 0, 1, 4, 0, 0, false).
		AddItem(table, 2, 0, 1, 4, 0, 0, true).
		AddItem(newTextView(menuBar, tview.AlignLeft), 3, 0, 1, 4, 0, 0, false)

	grid.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 'q' || event.Key() == tcell.KeyEsc {
			uiApp.app.Stop()
			os.Exit(0)
		} else if event.Key() == tcell.KeyLeft || event.Key() == tcell.KeyRight {
			return nil
		}
		return event
	})

	if err := uiApp.app.SetRoot(grid, true).Run(); err != nil {
		log.SetOutput(os.Stdout)
		log.Println("Unable to load the UI:", err)
		os.Exit(1)
	}
}

func getHeaderRow() string {
	var headers string
	for i, col := range columns {
		var header string
		if i == 0 {
			header = " " + col.name
		} else {
			header = col.name
		}
		headers += alignLeft(header, col.width)
	}
	return headers
}

func alignLeft(text string, len int) string {
	format := fmt.Sprintf("%%-%vs", len)
	return fmt.Sprintf(format, text)
}

func alignRight(text string, len int) string {
	format := fmt.Sprintf("%%%vs", len)
	return fmt.Sprintf(format, text)
}
