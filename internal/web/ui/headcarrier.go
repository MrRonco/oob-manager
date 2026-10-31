package ui

// headCarrier is a server page's view model whose head (with its action menus) was
// already built for this request; serverLayout reuses those menus for the phone bar
// instead of building them again.
type headCarrier interface{ serverHeadOf() serverHead }

func (v serverActivityView) serverHeadOf() serverHead { return v.Head }
func (v fanPageView) serverHeadOf() serverHead        { return v.Head }
func (v inventoryView) serverHeadOf() serverHead      { return v.Head }
func (v maintFormView) serverHeadOf() serverHead      { return v.Head }
func (v noteFormView) serverHeadOf() serverHead       { return v.Head }
func (v historyView) serverHeadOf() serverHead        { return v.Head }
func (v serverDetail) serverHeadOf() serverHead       { return v.Head }
func (v logsView) serverHeadOf() serverHead           { return v.Head }
func (v securityView) serverHeadOf() serverHead       { return v.Head }
